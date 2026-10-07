import { db, error, json, router } from '@appdeploy/sdk';

type Source =
  | 'apple_app_store'
  | 'instagram'
  | 'x'
  | 'facebook'
  | 'linkedin'
  | 'youtube'
  | 'tiktok'
  | 'google_play';
type SourceMode = 'live' | 'fixture' | 'fallback_fixture';
type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW';
type IncidentStatus =
  | 'new'
  | 'investigating'
  | 'confirmed'
  | 'resolved'
  | 'false_positive';

interface OfficialIdentity {
  platform: Source;
  value: string;
}
interface Brand {
  id: string;
  name: string;
  aliases: string[];
  domains: string[];
  description: string;
  officialIdentities: OfficialIdentity[];
}
interface Candidate {
  id: string;
  source: Source;
  sourceMode: SourceMode;
  displayName: string;
  handleOrPackage: string;
  publisher: string;
  description: string;
  url: string;
}
interface Signal {
  key: string;
  label: string;
  score: number;
  max: number;
  evidence: string;
}
interface AnalysisResult {
  kind: 'official' | 'detection';
  excluded: boolean;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  signals: Signal[];
  scamIndicators: string[];
  explanation: string;
  candidate: Candidate;
}
interface ScanRecord {
  brandId: string;
  source: Source;
  sourceMode: SourceMode;
  status: 'completed';
  createdAt: string;
  results: AnalysisResult[];
  warning?: string;
}
interface IncidentRecord {
  brandId: string;
  scanId: string;
  detectionId: string;
  severity: RiskLevel;
  status: IncidentStatus;
  decision: string | null;
  updatedAt: string;
  history: Array<{ at: string; from?: IncidentStatus; to: IncidentStatus }>;
}

const DEFAULT_BRAND: Brand = {
  id: 'paynova',
  name: 'PayNova',
  aliases: ['Pay Nova', 'PayNova Payments'],
  domains: ['paynova.example'],
  description: 'Digital payments and wallet platform',
  officialIdentities: [
    { platform: 'x', value: 'paynova' },
    { platform: 'apple_app_store', value: 'com.paynova.app' },
  ],
};

const confusable: Record<string, string> = {
  о: 'o',
  О: 'o',
  а: 'a',
  А: 'a',
  е: 'e',
  Е: 'e',
  і: 'i',
  І: 'i',
  р: 'p',
  Р: 'p',
  с: 'c',
  С: 'c',
  х: 'x',
  Х: 'x',
};
const buckets = new Map<string, { count: number; resetAt: number }>();

function deconfuse(value: string) {
  return [...value].map(char => confusable[char] ?? char).join('');
}
function normalize(value: string) {
  return deconfuse(value)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
}
function distance(left: string, right: string) {
  const matrix = Array.from({ length: left.length + 1 }, () =>
    Array(right.length + 1).fill(0)
  );
  for (let row = 0; row <= left.length; row += 1) matrix[row][0] = row;
  for (let col = 0; col <= right.length; col += 1) matrix[0][col] = col;
  for (let row = 1; row <= left.length; row += 1) {
    for (let col = 1; col <= right.length; col += 1) {
      matrix[row][col] = Math.min(
        matrix[row - 1][col] + 1,
        matrix[row][col - 1] + 1,
        matrix[row - 1][col - 1] + (left[row - 1] === right[col - 1] ? 0 : 1)
      );
    }
  }
  return matrix[left.length][right.length] as number;
}
function similarity(left: string, right: string) {
  const a = normalize(left);
  const b = normalize(right);
  if (!a || !b) return 0;
  return 1 - distance(a, b) / Math.max(a.length, b.length);
}
function riskLevel(score: number): RiskLevel {
  return score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW';
}
function isOfficial(brand: Brand, candidate: Candidate) {
  const identity = normalize(candidate.handleOrPackage);
  return brand.officialIdentities.some(
    item =>
      item.platform === candidate.source && normalize(item.value) === identity
  );
}

function analyzeCandidate(brand: Brand, candidate: Candidate): AnalysisResult {
  if (isOfficial(brand, candidate)) {
    return {
      kind: 'official',
      excluded: true,
      riskScore: null,
      riskLevel: null,
      signals: [],
      scamIndicators: [],
      explanation:
        'Exact registered official identity matched; excluded before threat scoring.',
      candidate,
    };
  }
  const protectedNames = [brand.name, ...brand.aliases];
  const nameSimilarity = Math.max(
    ...protectedNames.map(name => similarity(name, candidate.displayName))
  );
  const handleSimilarity = Math.max(
    ...protectedNames.map(name => similarity(name, candidate.handleOrPackage))
  );
  const protectedTokens = protectedNames.map(normalize).filter(Boolean);
  const candidateTokens = [
    normalize(candidate.displayName),
    normalize(candidate.handleOrPackage),
  ];
  const brandPrefix = candidateTokens.some(value =>
    protectedTokens.some(token => value.startsWith(token))
  )
    ? 1
    : 0;
  const nameScore = Math.round(
    Math.max(nameSimilarity, handleSimilarity, brandPrefix) * 30
  );
  const rawIdentity = `${candidate.displayName} ${candidate.handleOrPackage}`;
  const lookalikeScore =
    rawIdentity !== deconfuse(rawIdentity)
      ? 15
      : nameSimilarity > 0.72 && nameSimilarity < 0.99
        ? 8
        : 0;
  const descriptionSimilarity = Math.max(
    ...protectedNames.map(name =>
      similarity(name, candidate.description.split(/\s+/).slice(0, 8).join(' '))
    )
  );
  const descriptionScore = Math.min(15, Math.round(descriptionSimilarity * 15));
  const publisherScore = normalize(candidate.publisher).includes(
    normalize(brand.name)
  )
    ? 0
    : 20;
  const scamIndicators: string[] = [];
  const description = candidate.description.toLowerCase();
  if (/urgent|verify|suspend|locked|security alert/.test(description))
    scamIndicators.push('urgent or verification language');
  if (/link|click|login|password|otp/.test(description))
    scamIndicators.push('credential or external-link prompt');
  try {
    const host = new URL(candidate.url).hostname.replace(/^www\./, '');
    const knownDomain = brand.domains.some(
      domain => host === domain || host.endsWith(`.${domain}`)
    );
    if (
      !knownDomain &&
      candidate.source !== 'apple_app_store' &&
      (nameSimilarity >= 0.75 || lookalikeScore > 0)
    )
      scamIndicators.push('unrecognized external domain');
  } catch {
    scamIndicators.push('malformed external URL');
  }
  const signals: Signal[] = [
    {
      key: 'name',
      label: 'Name similarity',
      score: nameScore,
      max: 30,
      evidence: `Similarity to protected brand: ${Math.round(nameSimilarity * 100)}%`,
    },
    {
      key: 'lookalike',
      label: 'Look-alike / homoglyph',
      score: lookalikeScore,
      max: 15,
      evidence: lookalikeScore
        ? 'Confusable or near-copy identity detected'
        : 'No strong look-alike signal',
    },
    {
      key: 'logo',
      label: 'Logo similarity',
      score: 0,
      max: 20,
      evidence: 'No image hash supplied for this candidate',
    },
    {
      key: 'description',
      label: 'Description similarity',
      score: descriptionScore,
      max: 15,
      evidence: 'Text overlap with protected brand description/name',
    },
    {
      key: 'publisher',
      label: 'Publisher mismatch',
      score: publisherScore,
      max: 20,
      evidence: publisherScore
        ? 'Publisher is not the registered brand'
        : 'Publisher matches brand',
    },
  ];
  const baseScore = signals.reduce((total, signal) => total + signal.score, 0);
  const multiplier = Math.min(1.2, 1 + scamIndicators.length * 0.1);
  let score = Math.min(100, Math.round(baseScore * multiplier));
  if (
    nameSimilarity < 0.7 &&
    lookalikeScore === 0 &&
    scamIndicators.length === 0
  )
    score = Math.min(score, 25);
  return {
    kind: 'detection',
    excluded: false,
    riskScore: score,
    riskLevel: riskLevel(score),
    signals,
    scamIndicators,
    explanation: `Explainable weighted evidence score ${score}/100; use for analyst prioritization, not proof of fraud.`,
    candidate,
  };
}

const fixtureBase: Partial<
  Record<Source, Array<Omit<Candidate, 'source' | 'sourceMode'>>>
> = {
  instagram: [
    {
      id: 'ig-1',
      displayName: 'PayNоva Support',
      handleOrPackage: 'paynоva_support',
      publisher: 'Unknown',
      description: 'URGENT verify your PayNova account using the link below',
      url: 'https://paynova-secure.example.net',
    },
    {
      id: 'ig-2',
      displayName: 'PayNova Helpdesk',
      handleOrPackage: 'paynova_helpdesk',
      publisher: 'Fast Assist',
      description:
        'Security alert: click the link to login and unlock your account',
      url: 'https://secure-paynova-login.example.org',
    },
    {
      id: 'ig-3',
      displayName: 'Pavel Novak',
      handleOrPackage: 'paynovak',
      publisher: 'Pavel Novak',
      description: 'Landscape photographer and travel writer',
      url: 'https://example.org/pavel',
    },
  ],
  x: [
    {
      id: 'x-official',
      displayName: 'PayNova',
      handleOrPackage: 'paynova',
      publisher: 'PayNova',
      description: 'Official PayNova payments',
      url: 'https://paynova.example',
    },
    {
      id: 'x-homo',
      displayName: 'PayNоva Security',
      handleOrPackage: 'paynоva_security',
      publisher: 'Unknown',
      description: 'URGENT verify account now',
      url: 'https://paynova-alert.example.net',
    },
    {
      id: 'x-benign',
      displayName: 'Pavel Novak',
      handleOrPackage: 'paynovak',
      publisher: 'Pavel Novak',
      description: 'Landscape photographer and travel writer',
      url: 'https://example.org/pavel',
    },
  ],
  facebook: [
    {
      id: 'fb-1',
      displayName: 'PayNova Security',
      handleOrPackage: 'paynova.security',
      publisher: 'Unknown',
      description: 'Verify your account urgently',
      url: 'https://verify-paynova.example.org',
    },
    {
      id: 'fb-2',
      displayName: 'Pay Nova Fans',
      handleOrPackage: 'paynovafans',
      publisher: 'Community',
      description: 'Unofficial fan community',
      url: 'https://facebook.com/example',
    },
    {
      id: 'fb-3',
      displayName: 'Nova Pay Studio',
      handleOrPackage: 'novapaystudio',
      publisher: 'Nova Studio',
      description: 'Design studio',
      url: 'https://example.org',
    },
  ],
  linkedin: [
    {
      id: 'li-1',
      displayName: 'PayNova Careers',
      handleOrPackage: 'paynova-careers',
      publisher: 'Unknown',
      description: 'Send OTP to verify job application',
      url: 'https://paynova-jobs.example.org',
    },
    {
      id: 'li-2',
      displayName: 'PayNova Payments',
      handleOrPackage: 'paynova-payments',
      publisher: 'Unknown',
      description: 'Payments support',
      url: 'https://linkedin.com/company/example',
    },
    {
      id: 'li-3',
      displayName: 'Nova Payments Research',
      handleOrPackage: 'nova-payments-research',
      publisher: 'Research Group',
      description: 'Academic payments research',
      url: 'https://example.edu',
    },
  ],
  youtube: [
    {
      id: 'yt-1',
      displayName: 'PayNova Official Help',
      handleOrPackage: '@paynova-help',
      publisher: 'Unknown',
      description: 'Account locked? click login link',
      url: 'https://youtube.com/@example',
    },
    {
      id: 'yt-2',
      displayName: 'PayNova Review',
      handleOrPackage: '@paynovareview',
      publisher: 'Tech Reviews',
      description: 'Independent product review',
      url: 'https://youtube.com/@review',
    },
    {
      id: 'yt-3',
      displayName: 'Pavel Novak Travel',
      handleOrPackage: '@paynovaktravel',
      publisher: 'Pavel Novak',
      description: 'Travel videos',
      url: 'https://youtube.com/@travel',
    },
  ],
  tiktok: [
    {
      id: 'tt-1',
      displayName: 'PayNоva Verify',
      handleOrPackage: 'paynоva_verify',
      publisher: 'Unknown',
      description: 'URGENT verify account now',
      url: 'https://paynova-verify.example.net',
    },
    {
      id: 'tt-2',
      displayName: 'PayNova Tips',
      handleOrPackage: 'paynovatips',
      publisher: 'Creator',
      description: 'Unofficial app tips',
      url: 'https://tiktok.com/@tips',
    },
    {
      id: 'tt-3',
      displayName: 'Pay Novak',
      handleOrPackage: 'paynovak',
      publisher: 'Pay Novak',
      description: 'Comedy creator',
      url: 'https://tiktok.com/@paynovak',
    },
  ],
  google_play: [
    {
      id: 'gp-1',
      displayName: 'PayNova Wallet Secure',
      handleOrPackage: 'com.secure.paynova',
      publisher: 'Secure Apps LLC',
      description: 'Verify login to activate wallet',
      url: 'https://play.google.com/store/apps/details?id=com.secure.paynova',
    },
    {
      id: 'gp-2',
      displayName: 'PayNova Guide',
      handleOrPackage: 'com.guide.paynova',
      publisher: 'Guides Inc',
      description: 'Unofficial user guide',
      url: 'https://play.google.com/store/apps/details?id=com.guide.paynova',
    },
    {
      id: 'gp-3',
      displayName: 'NovaPay Calculator',
      handleOrPackage: 'com.novapay.calc',
      publisher: 'Utility Labs',
      description: 'Calculator utility',
      url: 'https://play.google.com/store/apps/details?id=com.novapay.calc',
    },
  ],
};

const appleFallback: Array<Omit<Candidate, 'source' | 'sourceMode'>> = [
  {
    id: 'apple-fallback-1',
    displayName: 'PayNova Account Verify',
    handleOrPackage: 'com.fake.paynova.verify',
    publisher: 'Unknown Labs',
    description: 'URGENT verify your PayNova account',
    url: 'https://apps.apple.com/app/id9001',
  },
  {
    id: 'apple-fallback-2',
    displayName: 'PayNova Companion',
    handleOrPackage: 'com.companion.paynova',
    publisher: 'Companion Apps',
    description: 'Unofficial companion',
    url: 'https://apps.apple.com/app/id9002',
  },
  {
    id: 'apple-fallback-3',
    displayName: 'Nova Payment Tracker',
    handleOrPackage: 'com.nova.tracker',
    publisher: 'Tracker Studio',
    description: 'Track personal expenses',
    url: 'https://apps.apple.com/app/id9003',
  },
];

function fixtureCandidates(source: Source, mode: SourceMode): Candidate[] {
  const rows =
    source === 'apple_app_store'
      ? appleFallback
      : (fixtureBase[source] ?? fixtureBase.instagram ?? []);
  return rows.map(row => ({ ...row, source, sourceMode: mode }));
}

async function searchApple(
  term: string,
  country: string,
  limit: number
): Promise<Candidate[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const url = new URL('https://itunes.apple.com/search');
    url.search = new URLSearchParams({
      term,
      country,
      entity: 'software',
      limit: String(Math.min(limit, 10)),
    }).toString();
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) throw new Error(`Apple upstream ${response.status}`);
    const payload = (await response.json()) as {
      results?: Array<Record<string, unknown>>;
    };
    return (payload.results ?? []).slice(0, 10).map(item => ({
      id: `apple:${String(item.trackId ?? crypto.randomUUID())}`,
      source: 'apple_app_store',
      sourceMode: 'live',
      displayName: String(item.trackName ?? 'Unknown app'),
      handleOrPackage: String(item.bundleId ?? item.trackId ?? 'unknown'),
      publisher: String(item.sellerName ?? 'Unknown publisher'),
      description: String(item.description ?? ''),
      url: String(item.trackViewUrl ?? 'https://apps.apple.com/'),
    }));
  } finally {
    clearTimeout(timer);
  }
}

function limited(key: string, limit: number) {
  const now = Date.now();
  const current = buckets.get(key);
  if (!current || now >= current.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + 60_000 });
    return false;
  }
  if (current.count >= limit) return true;
  current.count += 1;
  return false;
}

async function ensureBrand(): Promise<Brand> {
  const { items } = await db.list<Brand>('guard_brands', { limit: 10 });
  const existing = items.find(
    item => item.id === DEFAULT_BRAND.id || item.name === DEFAULT_BRAND.name
  );
  if (existing)
    return {
      id: existing.id === DEFAULT_BRAND.id ? existing.id : DEFAULT_BRAND.id,
      name: existing.name,
      aliases: existing.aliases,
      domains: existing.domains,
      description: existing.description,
      officialIdentities: existing.officialIdentities,
    };
  await db.add('guard_brands', [DEFAULT_BRAND]);
  return DEFAULT_BRAND;
}

async function saveBrand(brand: Brand) {
  const { items } = await db.list<Brand>('guard_brands', { limit: 10 });
  const existing = items.find(
    item => item.name === brand.name || item.id === brand.id
  );
  if (existing) {
    const databaseId = existing.id;
    await db.update('guard_brands', [{ id: databaseId, record: brand }]);
  } else {
    await db.add('guard_brands', [brand]);
  }
  return brand;
}

function validBrand(value: unknown): value is Brand {
  if (!value || typeof value !== 'object') return false;
  const brand = value as Partial<Brand>;
  return (
    typeof brand.id === 'string' &&
    typeof brand.name === 'string' &&
    brand.name.trim().length >= 2 &&
    Array.isArray(brand.aliases) &&
    Array.isArray(brand.domains) &&
    brand.domains.length > 0 &&
    brand.domains.every(
      domain => typeof domain === 'string' && domain.trim().length >= 3
    ) &&
    typeof brand.description === 'string' &&
    Array.isArray(brand.officialIdentities)
  );
}

const VALID_SOURCES: Source[] = [
  'apple_app_store',
  'instagram',
  'x',
  'facebook',
  'linkedin',
  'youtube',
  'tiktok',
  'google_play',
];

function candidateValidationMessage(candidate: Partial<Candidate> | undefined) {
  if (!candidate) return 'Candidate identity is required';
  if (!VALID_SOURCES.includes(candidate.source as Source))
    return 'A valid candidate source is required';
  if (typeof candidate.displayName !== 'string' || !candidate.displayName.trim())
    return 'Candidate display name is required';
  if (
    typeof candidate.handleOrPackage !== 'string' ||
    !candidate.handleOrPackage.trim()
  )
    return 'Candidate handle or package ID is required';
  if (typeof candidate.publisher !== 'string' || !candidate.publisher.trim())
    return 'Candidate publisher is required';
  if (
    typeof candidate.description !== 'string' ||
    !candidate.description.trim()
  )
    return 'Candidate description is required';
  if (typeof candidate.url !== 'string' || !candidate.url.trim())
    return 'A valid candidate URL is required';
  try {
    const parsed = new URL(candidate.url.trim());
    if (!['http:', 'https:'].includes(parsed.protocol))
      return 'A valid candidate URL is required';
  } catch {
    return 'A valid candidate URL is required';
  }
  return null;
}

function legalTransition(from: IncidentStatus, to: IncidentStatus) {
  const allowed: Record<IncidentStatus, IncidentStatus[]> = {
    new: ['investigating'],
    investigating: ['confirmed', 'false_positive'],
    confirmed: ['resolved'],
    resolved: [],
    false_positive: [],
  };
  return allowed[from].includes(to);
}

export const handler = router({
  'GET /api/_healthcheck': [
    async () =>
      json({
        ok: true,
        service: 'paynova-guard',
        status: 'ready',
        version: 'round-one',
        persistence: 'appdeploy-database',
      }),
  ],
  'GET /api/state': [
    async () => {
      try {
        const brand = await ensureBrand();
        const scanPage = await db.list<ScanRecord>('guard_scans', {
          limit: 40,
        });
        const incidentPage = await db.list<IncidentRecord>('guard_incidents', {
          limit: 40,
        });
        const scans = scanPage.items
          .map(item => ({ ...item, id: item.id }))
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const incidents = incidentPage.items
          .map(item => ({ ...item, id: item.id }))
          .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        return json({ ok: true, data: { brand, scans, incidents } });
      } catch (cause) {
        console.error('state_load_failed', cause);
        return json(
          {
            ok: false,
            error: {
              code: 'PERSISTENCE_UNAVAILABLE',
              message: 'Unable to load persisted state',
            },
          },
          503
        );
      }
    },
  ],
  'POST /api/brands': [
    async ({ body }) => {
      if (!validBrand(body))
        return json(
          {
            ok: false,
            error: {
              code: 'VALIDATION_ERROR',
              message:
                'Brand name and at least one official domain are required',
            },
          },
          400
        );
      try {
        const brand = await saveBrand(body);
        return json({ ok: true, data: brand }, 201);
      } catch (cause) {
        console.error('brand_save_failed', cause);
        return json(
          {
            ok: false,
            error: {
              code: 'PERSISTENCE_UNAVAILABLE',
              message: 'Unable to save protected brand',
            },
          },
          503
        );
      }
    },
  ],
  'POST /api/analyze': [
    async ({ body }) => {
      if (limited('analyze', 30))
        return json(
          {
            ok: false,
            error: {
              code: 'RATE_LIMITED',
              message: 'Too many analyze requests',
            },
          },
          429
        );
      const payload = body as {
        brandId?: string;
        candidate?: Partial<Candidate>;
      };
      const candidate = payload.candidate;
      const validationMessage = candidateValidationMessage(candidate);
      if (validationMessage)
        return json(
          {
            ok: false,
            error: {
              code: 'VALIDATION_ERROR',
              message: validationMessage,
            },
          },
          400
        );
      const brand = await ensureBrand();
      const normalized: Candidate = {
        id: candidate.id ?? `manual-${Date.now()}`,
        source: candidate.source as Source,
        sourceMode: candidate.sourceMode ?? 'fixture',
        displayName: candidate.displayName!.trim(),
        handleOrPackage: candidate.handleOrPackage!.trim(),
        publisher: candidate.publisher!.trim(),
        description: candidate.description!.trim(),
        url: candidate.url!.trim(),
      };
      return json({ ok: true, data: analyzeCandidate(brand, normalized) });
    },
  ],
  'POST /api/scans': [
    async ({ body }) => {
      if (limited('scan', 6))
        return json(
          {
            ok: false,
            error: { code: 'RATE_LIMITED', message: 'Too many scan requests' },
          },
          429
        );
      const payload = body as {
        source?: Source;
        mode?: 'live' | 'fixture';
        query?: string;
        country?: string;
        limit?: number;
      };
      if (!payload.source || !payload.mode)
        return json(
          {
            ok: false,
            error: {
              code: 'VALIDATION_ERROR',
              message: 'source and mode are required',
            },
          },
          400
        );
      if (payload.mode === 'live' && payload.source !== 'apple_app_store')
        return json(
          {
            ok: false,
            error: {
              code: 'UNSUPPORTED_SOURCE',
              message: 'Live mode is only supported for Apple App Store',
            },
          },
          422
        );
      const brand = await ensureBrand();
      let candidates: Candidate[];
      let sourceMode: SourceMode = payload.mode;
      let warning: string | undefined;
      if (payload.mode === 'live') {
        try {
          candidates = await searchApple(
            payload.query ?? brand.name,
            payload.country ?? 'in',
            Math.min(payload.limit ?? 10, 10)
          );
        } catch (cause) {
          console.warn('apple_live_fallback', cause);
          sourceMode = 'fallback_fixture';
          warning =
            'Live App Store lookup was unavailable; deterministic fallback data was used.';
          candidates = fixtureCandidates('apple_app_store', 'fallback_fixture');
        }
      } else {
        candidates = fixtureCandidates(payload.source, 'fixture');
      }
      const results = candidates
        .map(candidate => analyzeCandidate(brand, candidate))
        .sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1));
      const record: ScanRecord = {
        brandId: brand.id,
        source: payload.source,
        sourceMode,
        status: 'completed',
        createdAt: new Date().toISOString(),
        results,
        ...(warning ? { warning } : {}),
      };
      try {
        const [id] = await db.add('guard_scans', [record]);
        if (!id) throw new Error('scan_add_failed');
        return json({ ok: true, data: { ...record, id } }, 201);
      } catch (cause) {
        console.error('scan_save_failed', cause);
        return json(
          {
            ok: false,
            error: {
              code: 'PERSISTENCE_UNAVAILABLE',
              message: 'Scan completed but could not be persisted',
            },
          },
          503
        );
      }
    },
  ],
  'POST /api/incidents': [
    async ({ body }) => {
      const payload = body as {
        brandId?: string;
        scanId?: string;
        detectionId?: string;
        severity?: RiskLevel;
      };
      if (
        !payload.brandId ||
        !payload.scanId ||
        !payload.detectionId ||
        !payload.severity
      )
        return json(
          {
            ok: false,
            error: {
              code: 'VALIDATION_ERROR',
              message: 'brandId, scanId, detectionId and severity are required',
            },
          },
          400
        );
      const page = await db.list<IncidentRecord>('guard_incidents', {
        limit: 50,
      });
      const duplicate = page.items.find(
        item =>
          item.detectionId === payload.detectionId &&
          !['resolved', 'false_positive'].includes(item.status)
      );
      if (duplicate)
        return json(
          {
            ok: false,
            error: {
              code: 'DUPLICATE_INCIDENT',
              message: 'An open incident already exists for this detection',
            },
          },
          409
        );
      const now = new Date().toISOString();
      const record: IncidentRecord = {
        brandId: payload.brandId,
        scanId: payload.scanId,
        detectionId: payload.detectionId,
        severity: payload.severity,
        status: 'new',
        decision: null,
        updatedAt: now,
        history: [{ at: now, to: 'new' }],
      };
      const [id] = await db.add('guard_incidents', [record]);
      if (!id) return error('Incident could not be persisted', 503);
      return json({ ok: true, data: { ...record, id } }, 201);
    },
  ],
  'PUT /api/incidents/:id': [
    async ({ params, body }) => {
      const payload = body as { status?: IncidentStatus };
      if (!payload.status)
        return json(
          {
            ok: false,
            error: { code: 'VALIDATION_ERROR', message: 'status is required' },
          },
          400
        );
      const [existing] = await db.get<IncidentRecord>('guard_incidents', [
        params.id,
      ]);
      if (!existing)
        return json(
          {
            ok: false,
            error: {
              code: 'INCIDENT_NOT_FOUND',
              message: 'Incident not found',
            },
          },
          404
        );
      if (!legalTransition(existing.status, payload.status))
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_TRANSITION',
              message: `${existing.status} cannot transition to ${payload.status}`,
            },
          },
          409
        );
      const now = new Date().toISOString();
      const updated: IncidentRecord = {
        ...existing,
        status: payload.status,
        updatedAt: now,
        history: [
          ...existing.history,
          { at: now, from: existing.status, to: payload.status },
        ],
      };
      const [saved] = await db.update('guard_incidents', [
        { id: params.id, record: updated },
      ]);
      if (!saved) return error('Incident update failed', 503);
      return json({ ok: true, data: { ...updated, id: params.id } });
    },
  ],
  'POST /api/incidents/:id/false-positive': [
    async ({ params }) => {
      const [existing] = await db.get<IncidentRecord>('guard_incidents', [
        params.id,
      ]);
      if (!existing)
        return json(
          {
            ok: false,
            error: {
              code: 'INCIDENT_NOT_FOUND',
              message: 'Incident not found',
            },
          },
          404
        );
      if (!legalTransition(existing.status, 'false_positive'))
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_TRANSITION',
              message: `${existing.status} cannot transition to false_positive`,
            },
          },
          409
        );
      const now = new Date().toISOString();
      const updated: IncidentRecord = {
        ...existing,
        status: 'false_positive',
        decision: 'Marked false positive',
        updatedAt: now,
        history: [
          ...existing.history,
          { at: now, from: existing.status, to: 'false_positive' },
        ],
      };
      const [saved] = await db.update('guard_incidents', [
        { id: params.id, record: updated },
      ]);
      if (!saved) return error('Incident update failed', 503);
      return json({ ok: true, data: { ...updated, id: params.id } });
    },
  ],
});
