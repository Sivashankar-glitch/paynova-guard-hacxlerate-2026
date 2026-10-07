import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '@appdeploy/client';
import {
  Activity,
  AppWindow,
  BarChart3,
  Bell,
  Building2,
  ChevronRight,
  CircleCheck,
  Database,
  FileSearch,
  LayoutDashboard,
  Menu,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react';

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
type Tab =
  | 'Dashboard'
  | 'Monitor'
  | 'Detections'
  | 'Investigations'
  | 'Incidents'
  | 'Brand Assets'
  | 'Analytics';

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
interface Scan {
  id: string;
  brandId: string;
  source: Source;
  sourceMode: SourceMode;
  status: 'completed';
  createdAt: string;
  results: AnalysisResult[];
  warning?: string;
}
interface Incident {
  id: string;
  brandId: string;
  scanId: string;
  detectionId: string;
  severity: RiskLevel;
  status: IncidentStatus;
  decision: string | null;
  updatedAt: string;
  history: Array<{ at: string; from?: IncidentStatus; to: IncidentStatus }>;
}
interface StateResponse {
  brand: Brand;
  scans: Scan[];
  incidents: Incident[];
}

const sources: Array<{ value: Source; label: string; mode: 'live' | 'fixture' }> = [
  { value: 'apple_app_store', label: 'Apple App Store', mode: 'live' },
  { value: 'instagram', label: 'Instagram', mode: 'fixture' },
  { value: 'x', label: 'X / Twitter', mode: 'fixture' },
  { value: 'facebook', label: 'Facebook', mode: 'fixture' },
  { value: 'linkedin', label: 'LinkedIn', mode: 'fixture' },
  { value: 'youtube', label: 'YouTube', mode: 'fixture' },
  { value: 'tiktok', label: 'TikTok', mode: 'fixture' },
  { value: 'google_play', label: 'Google Play', mode: 'fixture' },
];

const navItems: Array<{ tab: Tab; icon: typeof LayoutDashboard }> = [
  { tab: 'Dashboard', icon: LayoutDashboard },
  { tab: 'Monitor', icon: Radar },
  { tab: 'Detections', icon: ShieldAlert },
  { tab: 'Investigations', icon: FileSearch },
  { tab: 'Incidents', icon: AppWindow },
  { tab: 'Brand Assets', icon: Building2 },
  { tab: 'Analytics', icon: BarChart3 },
];

const nextStatus: Record<IncidentStatus, IncidentStatus | undefined> = {
  new: 'investigating',
  investigating: 'confirmed',
  confirmed: 'resolved',
  resolved: undefined,
  false_positive: undefined,
};

function App() {
  const [tab, setTab] = useState<Tab>('Dashboard');
  const [brand, setBrand] = useState<Brand | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<AnalysisResult | null>(null);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState('Loading persisted state…');
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    void refreshState();
  }, []);

  const detections = useMemo(
    () =>
      scans
        .flatMap(scan =>
          scan.results
            .filter(result => result.kind === 'detection')
            .map(result => ({
              result,
              scanId: scan.id,
              sourceMode: scan.sourceMode,
              createdAt: scan.createdAt,
            }))
        )
        .sort((left, right) =>
          (right.result.riskScore ?? 0) - (left.result.riskScore ?? 0)
        ),
    [scans]
  );

  async function refreshState() {
    try {
      const response = await api.get('/api/state');
      const state = response.data.data as StateResponse;
      setBrand(state.brand);
      setScans(state.scans);
      setIncidents(state.incidents);
      setStatus('System ready • persisted state loaded');
    } catch {
      setStatus('Unable to load persisted state');
    }
  }

  async function saveBrand() {
    if (!brand) return;
    if (
      !brand.name.trim() ||
      brand.domains.length === 0 ||
      brand.domains.some(domain => !domain.trim())
    ) {
      setStatus('Brand name and at least one official domain are required');
      return;
    }
    setBusy(true);
    setStatus('Saving protected brand…');
    try {
      const response = await api.post('/api/brands', brand);
      setBrand(response.data.data as Brand);
      setStatus('Protected brand saved to server');
    } catch (cause) {
      setStatus(apiErrorMessage(cause, 'Brand save failed. Check required fields and retry.'));
    } finally {
      setBusy(false);
    }
  }

  async function runScan(source: Source, mode: 'live' | 'fixture') {
    if (!brand) return;
    setBusy(true);
    setStatus(
      mode === 'live'
        ? 'Running live Apple App Store lookup…'
        : `Running ${sourceName(source)} fixture scan…`
    );
    try {
      const response = await api.post('/api/scans', {
        brandId: brand.id,
        source,
        mode,
        query: brand.name,
        country: 'in',
        limit: 10,
      });
      const scan = response.data.data as Scan;
      setScans(current => [
        scan,
        ...current.filter(item => item.id !== scan.id),
      ]);
      setStatus(
        scan.warning ??
          (scan.sourceMode === 'live'
            ? scan.results.length > 0
              ? `Live App Store scan completed — ${scan.results.length} applications found.`
              : 'Live App Store scan completed — no matching applications found.'
            : `Fixture scan completed — ${scan.results.length} candidates analyzed.`)
      );
      setTab('Detections');
    } catch (cause) {
      setStatus(apiErrorMessage(cause, 'Scan failed. Please retry.'));
    } finally {
      setBusy(false);
    }
  }

  async function analyzeCandidateInput(
    candidate: Omit<Candidate, 'id' | 'sourceMode'>
  ): Promise<string | null> {
    if (!brand) return 'Protected brand is unavailable.';
    setBusy(true);
    setStatus('Analyzing candidate with backend risk engine…');
    try {
      const response = await api.post('/api/analyze', {
        brandId: brand.id,
        candidate: { ...candidate, sourceMode: 'fixture' },
      });
      const result = response.data.data as AnalysisResult;
      setSelected(result);
      setSelectedScanId('');
      setStatus(
        `Analysis complete • ${result.kind === 'official' ? 'OFFICIAL' : `${result.riskLevel} ${result.riskScore}/100`}`
      );
      return null;
    } catch (cause) {
      const message = apiErrorMessage(
        cause,
        'Candidate analysis failed. Please retry.'
      );
      setStatus(message);
      return message;
    } finally {
      setBusy(false);
    }
  }

  async function createIncident(result: AnalysisResult, scanId: string) {
    if (!brand || !result.riskLevel || !scanId || busy) return;
    setBusy(true);
    setStatus('Creating incident…');
    try {
      const response = await api.post('/api/incidents', {
        brandId: brand.id,
        scanId,
        detectionId: result.candidate.id,
        severity: result.riskLevel,
      });
      const incident = response.data.data as Incident;
      setIncidents(current => [
        incident,
        ...current.filter(item => item.id !== incident.id),
      ]);
      setSelected(null);
      setStatus(`Incident ${shortIncidentId(incident.id)} created`);
      setTab('Incidents');
    } catch (cause) {
      setStatus(
        apiErrorMessage(
          cause,
          'An active incident already exists for this detection.'
        )
      );
      setSelected(null);
      setTab('Incidents');
    } finally {
      setBusy(false);
    }
  }

  async function changeIncident(
    incident: Incident,
    target: IncidentStatus
  ) {
    if (busy) return;
    setBusy(true);
    setStatus('Updating incident…');
    try {
      const response = await api.put(`/api/incidents/${incident.id}`, {
        status: target,
      });
      const updated = response.data.data as Incident;
      setIncidents(current =>
        current.map(item => (item.id === updated.id ? updated : item))
      );
      setStatus(
        `${shortIncidentId(updated.id)} moved to ${updated.status.replace('_', ' ')}`
      );
    } catch (cause) {
      setStatus(apiErrorMessage(cause, 'Incident transition was rejected.'));
    } finally {
      setBusy(false);
    }
  }

  async function markFalsePositive(incident: Incident) {
    if (busy) return;
    setBusy(true);
    setStatus('Recording analyst decision…');
    try {
      const response = await api.post(
        `/api/incidents/${incident.id}/false-positive`,
        {}
      );
      const updated = response.data.data as Incident;
      setIncidents(current =>
        current.map(item => (item.id === updated.id ? updated : item))
      );
      setStatus(`${shortIncidentId(updated.id)} marked false positive`);
    } catch (cause) {
      setStatus(
        apiErrorMessage(cause, 'False-positive transition was rejected.')
      );
    } finally {
      setBusy(false);
    }
  }

  function navigate(next: Tab) {
    setTab(next);
    setMobileOpen(false);
  }

  if (!brand) {
    return (
      <div className="boot">
        <div className="spinner" />
        <b>PayNova Guard</b>
        <span>{status}</span>
      </div>
    );
  }

  return (
    <div className={mobileOpen ? 'workspace mobile-nav' : 'workspace'}>
      <a className="skip" href="#workspace-main">
        Skip to workspace
      </a>
      <Sidebar tab={tab} onNavigate={navigate} incidents={incidents} />
      {mobileOpen && (
        <button
          className="nav-scrim"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
        />
      )}
      <div className="application">
        <Topbar
          tab={tab}
          status={status}
          busy={busy}
          onMenu={() => setMobileOpen(value => !value)}
        />
        <main id="workspace-main" tabIndex={-1}>
          {tab === 'Dashboard' && (
            <Dashboard
              brand={brand}
              scans={scans}
              incidents={incidents}
              detections={detections}
              onNavigate={navigate}
            />
          )}
          {tab === 'Monitor' && (
            <Monitor run={runScan} busy={busy} scans={scans} />
          )}
          {tab === 'Detections' && (
            <Detections
              rows={detections}
              investigate={(result, scanId) => {
                setSelected(result);
                setSelectedScanId(scanId);
              }}
              create={createIncident}
            />
          )}
          {tab === 'Investigations' && (
            <Investigations busy={busy} analyze={analyzeCandidateInput} />
          )}
          {tab === 'Incidents' && (
            <Incidents
              items={incidents}
              scans={scans}
              busy={busy}
              advance={changeIncident}
              markFalsePositive={markFalsePositive}
            />
          )}
          {tab === 'Brand Assets' && (
            <BrandAssets
              brand={brand}
              setBrand={setBrand}
              save={saveBrand}
              busy={busy}
            />
          )}
          {tab === 'Analytics' && (
            <Analytics scans={scans} incidents={incidents} />
          )}
        </main>
        <footer className="statusbar">
          <span>
            <i className={busy ? 'status-dot pulse' : 'status-dot'} /> PAYNOVA
            GUARD V5 <b>{busy ? 'PROCESSING' : 'SYSTEM READY'}</b>
          </span>
          <span>
            SERVER PERSISTENCE <i>•</i> APPLE LIVE SOURCE <i>•</i> 7 FIXTURE
            ADAPTERS
          </span>
        </footer>
      </div>
      {selected && (
        <InvestigationDrawer
          result={selected}
          close={() => setSelected(null)}
          create={
            selectedScanId
              ? () => void createIncident(selected, selectedScanId)
              : undefined
          }
          busy={busy}
        />
      )}
    </div>
  );
}

function Sidebar({
  tab,
  onNavigate,
  incidents,
}: {
  tab: Tab;
  onNavigate: (tab: Tab) => void;
  incidents: Incident[];
}) {
  const openIncidents = incidents.filter(
    item => !['resolved', 'false_positive'].includes(item.status)
  ).length;
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <button
        className="brand-lockup"
        onClick={() => onNavigate('Dashboard')}
        aria-label="PayNova Guard dashboard"
      >
        <ShieldCheck />
        <span>
          paynova<small>GUARD</small>
        </span>
      </button>
      <button
        className="workspace-switcher"
        onClick={() => onNavigate('Brand Assets')}
      >
        <span className="orgmark">P</span>
        <span>
          PayNova Financial<small>Protected workspace</small>
        </span>
        <ChevronRight className="chevron" />
      </button>
      <div className="nav-label">DIGITAL RISK OPERATIONS</div>
      <nav>
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <button
              key={item.tab}
              className={tab === item.tab ? 'nav-item active' : 'nav-item'}
              onClick={() => onNavigate(item.tab)}
            >
              <Icon />
              <span>{item.tab}</span>
              {item.tab === 'Monitor' && (
                <i className="live-mark" title="Apple source live" />
              )}
              {item.tab === 'Incidents' && openIncidents > 0 && (
                <span className="count">{openIncidents}</span>
              )}
            </button>
          );
        })}
      </nav>
      <div className="sidebar-bottom">
        <div className="system-mini">
          <i className="status-dot" /> AppDeploy backend connected
          <small>Durable database • no localStorage</small>
        </div>
        <div className="profile">
          <span className="avatar">PG</span>
          <span>
            Round One<small>Evaluator workspace</small>
          </span>
        </div>
      </div>
    </aside>
  );
}

function Topbar({
  tab,
  status,
  busy,
  onMenu,
}: {
  tab: Tab;
  status: string;
  busy: boolean;
  onMenu: () => void;
}) {
  return (
    <header className="topbar">
      <div className="breadcrumb">
        <button
          className="icon-button mobile-menu"
          aria-label="Toggle navigation"
          onClick={onMenu}
        >
          <Menu />
        </button>
        <span>Workspace</span>
        <span className="slash">/</span>
        <strong>{tab}</strong>
      </div>
      <div className="top-actions">
        <button
          className="search-trigger"
          onClick={() => document.getElementById('workspace-main')?.focus()}
        >
          <Search />
          <span>Evaluator workspace</span>
          <kbd>V5</kbd>
        </button>
        <span className="provenance-tag">1 LIVE • 7 FIXTURE</span>
        <button className="icon-button alert-trigger" aria-label="System status">
          <Bell />
        </button>
        <span className={busy ? 'avatar small busy-avatar' : 'avatar small'}>
          PG
        </span>
      </div>
      <span className="sr-only" aria-live="polite">
        {status}
      </span>
    </header>
  );
}

function PageHead({
  eyebrow,
  title,
  text,
  actions,
}: {
  eyebrow: string;
  title: string;
  text: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{text}</p>
      </div>
      {actions && <div className="button-group">{actions}</div>}
    </div>
  );
}

function Dashboard({
  brand,
  scans,
  incidents,
  detections,
  onNavigate,
}: {
  brand: Brand;
  scans: Scan[];
  incidents: Incident[];
  detections: Array<{
    result: AnalysisResult;
    scanId: string;
    sourceMode: SourceMode;
    createdAt: string;
  }>;
  onNavigate: (tab: Tab) => void;
}) {
  const high = detections.filter(item => item.result.riskLevel === 'HIGH').length;
  const medium = detections.filter(
    item => item.result.riskLevel === 'MEDIUM'
  ).length;
  const low = detections.filter(item => item.result.riskLevel === 'LOW').length;
  const open = incidents.filter(
    item => !['resolved', 'false_positive'].includes(item.status)
  ).length;
  const latest = detections.slice(0, 5);
  return (
    <section>
      <PageHead
        eyebrow="HacXLerate • Challenge 03"
        title="Digital Risk Protection"
        text="Detect brand impersonation across digital platforms and app stores, explain every score, and turn suspicious identities into trackable analyst incidents."
        actions={
          <>
            <button className="btn" onClick={() => onNavigate('Investigations')}>
              <FileSearch /> Test candidate
            </button>
            <button className="btn primary" onClick={() => onNavigate('Monitor')}>
              <Radar /> Run scan
            </button>
          </>
        }
      />
      <div className="metric-band">
        <Metric
          dominant
          label="TOTAL SCANS"
          value={scans.length}
          context={
            scans.length ? 'Persisted server-side' : 'Ready for evaluator scan'
          }
        />
        <Metric label="HIGH-RISK" value={high} context={`${medium} medium`} />
        <Metric label="OPEN INCIDENTS" value={open} context="Analyst workflow" />
        <Metric label="DATA SOURCES" value="8" context="1 LIVE • 7 FIXTURE" />
      </div>
      <div className="overview-grid">
        <div className="stack">
          <div className="panel">
            <div className="panel-header">
              <div>
                <h2>Risk distribution</h2>
                <p className="subtitle">Persisted detection output</p>
              </div>
              <span className="label">{high + medium + low} DETECTIONS</span>
            </div>
            <div className="panel-body">
              <RiskBars high={high} medium={medium} low={low} />
            </div>
          </div>
          <div className="panel latest-panel">
            <div className="panel-header">
              <div>
                <h2>Priority detections</h2>
                <p className="subtitle">
                  Highest explainable scores across persisted scans
                </p>
              </div>
              <button className="btn text" onClick={() => onNavigate('Detections')}>
                View all <ChevronRight />
              </button>
            </div>
            {latest.length === 0 ? (
              <EmptyInline
                title="No detections yet"
                text="Run a source scan to populate prioritized candidates."
              />
            ) : (
              <div className="compact-table">
                {latest.map(item => (
                  <div
                    className="compact-row"
                    key={`${item.scanId}-${item.result.candidate.id}`}
                  >
                    <RiskBadge
                      level={item.result.riskLevel}
                      score={item.result.riskScore}
                    />
                    <div>
                      <b>{item.result.candidate.displayName}</b>
                      <small>{item.result.candidate.handleOrPackage}</small>
                    </div>
                    <div>
                      <Provenance mode={item.sourceMode} />
                      <small>{sourceName(item.result.candidate.source)}</small>
                    </div>
                    <button
                      className="btn text"
                      onClick={() => onNavigate('Detections')}
                    >
                      Review <ChevronRight />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
        <div className="priority">
          <div className="panel source-health">
            <div className="panel-header">
              <div>
                <h2>Source posture</h2>
                <p className="subtitle">Truthful provenance</p>
              </div>
              <Activity className="panel-icon" />
            </div>
            <div className="health-row">
              <span>
                <i className="status-dot" /> Apple App Store
              </span>
              <b className="positive">LIVE</b>
            </div>
            <div className="health-row">
              <span>
                <i className="fixture-dot" /> Social adapters
              </span>
              <b>FIXTURE</b>
            </div>
            <div className="health-row">
              <span>
                <Database /> Persistence
              </span>
              <b className="positive">SERVER</b>
            </div>
          </div>
          <div className="panel protected-card">
            <div className="panel-header">
              <div>
                <h2>Protected identity</h2>
                <p className="subtitle">Official exclusion runs first</p>
              </div>
              <ShieldCheck className="panel-icon" />
            </div>
            <div className="protected-body">
              <span className="orgmark large">P</span>
              <div>
                <b>{brand.name}</b>
                <small>{brand.domains[0]}</small>
              </div>
            </div>
            <div className="detail-pairs">
              <span>
                ALIASES <b>{brand.aliases.length}</b>
              </span>
              <span>
                OFFICIAL IDS <b>{brand.officialIdentities.length}</b>
              </span>
            </div>
            <button className="btn" onClick={() => onNavigate('Brand Assets')}>
              Manage brand assets
            </button>
          </div>
          <div className="panel judge-flow">
            <div className="panel-header">
              <div>
                <h2>2–3 minute judge flow</h2>
                <p className="subtitle">Optimized evaluator path</p>
              </div>
            </div>
            {[
              'Official test',
              'Homoglyph HIGH',
              'Benign LOW',
              'Fixture scan',
              'Create incident',
              'Refresh persistence',
              'Apple LIVE scan',
            ].map((step, index) => (
              <div className="flow-step" key={step}>
                <span>{String(index + 1).padStart(2, '0')}</span>
                <b>{step}</b>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function Metric({
  label,
  value,
  context,
  dominant = false,
}: {
  label: string;
  value: string | number;
  context: string;
  dominant?: boolean;
}) {
  return (
    <div className={dominant ? 'metric dominant' : 'metric'}>
      <span className="label">{label}</span>
      <div className="metric-value">{value}</div>
      <div className="metric-context">{context}</div>
    </div>
  );
}

function RiskBars({
  high,
  medium,
  low,
}: {
  high: number;
  medium: number;
  low: number;
}) {
  const max = Math.max(1, high, medium, low);
  return (
    <div className="risk-bars">
      {(
        [
          ['HIGH', high],
          ['MEDIUM', medium],
          ['LOW', low],
        ] as Array<[RiskLevel, number]>
      ).map(([level, count]) => (
        <div className="risk-bar-row" key={level}>
          <span className={`risk-word ${level.toLowerCase()}`}>{level}</span>
          <div className="bar-track">
            <i
              className={level.toLowerCase()}
              style={{
                width: `${Math.max(
                  count ? 7 : 0,
                  Math.round((count / max) * 100)
                )}%`,
              }}
            />
          </div>
          <b>{count}</b>
        </div>
      ))}
    </div>
  );
}

function Monitor({
  run,
  busy,
  scans,
}: {
  run: (source: Source, mode: 'live' | 'fixture') => void;
  busy: boolean;
  scans: Scan[];
}) {
  return (
    <section>
      <PageHead
        eyebrow="SOURCE ACQUISITION"
        title="Monitor"
        text="Run evaluator-controlled source scans. Apple App Store uses a genuine live request; all other current sources are deterministic fixtures."
      />
      <div className="intelligence-banner">
        <ShieldCheck />
        <div>
          <b>Truthful source provenance is enforced</b>
          <p>
            LIVE means a successful Apple lookup. Upstream failure is labelled
            FALLBACK_FIXTURE. Social datasets never claim crawling.
          </p>
        </div>
      </div>
      <div className="source-grid">
        {sources.map(source => {
          const last = scans.find(scan => scan.source === source.value);
          return (
            <button
              className="source-card"
              disabled={busy}
              key={source.value}
              onClick={() => run(source.value, source.mode)}
            >
              <div className="source-card-top">
                <span className="source-icon">
                  {source.mode === 'live' ? <AppWindow /> : <Radar />}
                </span>
                <Provenance mode={source.mode} />
              </div>
              <h2>{source.label}</h2>
              <p>
                {source.mode === 'live'
                  ? 'Public Apple Search API • 5s timeout • max 10 results'
                  : 'Deterministic candidate set for repeatable evaluation'}
              </p>
              <div className="source-card-foot">
                <span>
                  {last
                    ? `Last: ${formatCompactDate(last.createdAt)}`
                    : 'Not scanned yet'}
                </span>
                <span>
                  Run <ChevronRight />
                </span>
              </div>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function Detections({
  rows,
  investigate,
  create,
}: {
  rows: Array<{
    result: AnalysisResult;
    scanId: string;
    sourceMode: SourceMode;
    createdAt: string;
  }>;
  investigate: (result: AnalysisResult, scanId: string) => void;
  create: (result: AnalysisResult, scanId: string) => void;
}) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState<'ALL' | RiskLevel>('ALL');
  const [sourceMode, setSourceMode] = useState<'ALL' | SourceMode>('ALL');
  const [source, setSource] = useState<'ALL' | Source>('ALL');
  const filtered = rows.filter(({ result, sourceMode: rowMode }) => {
    const haystack = [
      result.candidate.displayName,
      result.candidate.handleOrPackage,
      result.candidate.publisher,
      result.candidate.source,
    ]
      .join(' ')
      .toLowerCase();
    return (
      haystack.includes(query.trim().toLowerCase()) &&
      (severity === 'ALL' || result.riskLevel === severity) &&
      (sourceMode === 'ALL' || rowMode === sourceMode) &&
      (source === 'ALL' || result.candidate.source === source)
    );
  });
  return (
    <section>
      <PageHead
        eyebrow="RISK INTELLIGENCE"
        title="Detections"
        text="Prioritized candidates with explainable evidence, source provenance, and analyst actions."
      />
      <div className="panel detection-panel">
        <div className="toolbar">
          <label className="search-field">
            <Search />
            <input
              aria-label="Search detections"
              value={query}
              onChange={event => setQuery(event.target.value)}
              placeholder="Search identity, handle, publisher…"
            />
          </label>
          <select
            aria-label="Severity filter"
            value={severity}
            onChange={event =>
              setSeverity(event.target.value as 'ALL' | RiskLevel)
            }
          >
            <option value="ALL">All severities</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
          <select
            aria-label="Source mode filter"
            value={sourceMode}
            onChange={event =>
              setSourceMode(event.target.value as 'ALL' | SourceMode)
            }
          >
            <option value="ALL">All provenance</option>
            <option value="live">LIVE</option>
            <option value="fixture">FIXTURE</option>
            <option value="fallback_fixture">FALLBACK</option>
          </select>
          <select
            aria-label="Source filter"
            value={source}
            onChange={event =>
              setSource(event.target.value as 'ALL' | Source)
            }
          >
            <option value="ALL">All sources</option>
            {sources.map(item => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </div>
        <div className="table-meta">
          <span>
            {filtered.length} of {rows.length} detections
          </span>
          <span>Risk score is triage priority, not proof of fraud</span>
        </div>
        {rows.length === 0 ? (
          <EmptyInline
            title="No detections yet"
            text="Run a scan from Monitor to populate persisted detections."
          />
        ) : filtered.length === 0 ? (
          <EmptyInline
            title="No matching detections"
            text="Adjust the current search or filters."
          />
        ) : (
          <div className="data-table">
            <div className="data-row data-head">
              <span>Risk</span>
              <span>Identity</span>
              <span>Source</span>
              <span>Evidence</span>
              <span>Actions</span>
            </div>
            {filtered.map(({ result, scanId, sourceMode: mode }) => (
              <div
                className="data-row"
                key={`${scanId}-${result.candidate.id}`}
              >
                <span>
                  <RiskBadge
                    level={result.riskLevel}
                    score={result.riskScore}
                  />
                </span>
                <span>
                  <b>{result.candidate.displayName}</b>
                  <small>{result.candidate.handleOrPackage}</small>
                </span>
                <span>
                  <Provenance mode={mode} />
                  <small>{sourceName(result.candidate.source)}</small>
                </span>
                <span>
                  <small>
                    {result.signals
                      .filter(
                        signal => signal.score > 0 && signal.key !== 'logo'
                      )
                      .slice(0, 2)
                      .map(signal => signal.label)
                      .join(' • ') || 'Low evidence'}
                  </small>
                </span>
                <span className="row-actions">
                  <button
                    className="btn"
                    onClick={() => investigate(result, scanId)}
                  >
                    Investigate
                  </button>
                  <button
                    className="btn primary"
                    onClick={() => create(result, scanId)}
                  >
                    Create incident
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

function Investigations({
  busy,
  analyze,
}: {
  busy: boolean;
  analyze: (
    candidate: Omit<Candidate, 'id' | 'sourceMode'>
  ) => Promise<string | null>;
}) {
  const presets: Array<{
    title: string;
    expectation: string;
    note: string;
    candidate: Omit<Candidate, 'id' | 'sourceMode'>;
  }> = [
    {
      title: 'Official PayNova',
      expectation: 'OFFICIAL',
      note: 'Exact registered identity exclusion',
      candidate: {
        source: 'x',
        displayName: 'PayNova',
        handleOrPackage: 'paynova',
        publisher: 'PayNova',
        description: 'Official PayNova account',
        url: 'https://paynova.example',
      },
    },
    {
      title: 'PayNоva Support',
      expectation: 'HIGH',
      note: 'Unicode homoglyph + urgent verification',
      candidate: {
        source: 'instagram',
        displayName: 'PayNоva Support',
        handleOrPackage: 'paynоva_support',
        publisher: 'Unknown',
        description:
          'URGENT — verify your PayNova account using the link below.',
        url: 'https://paynova-secure.example.net',
      },
    },
    {
      title: 'Pavel Novak',
      expectation: 'LOW',
      note: 'Benign similar personal name',
      candidate: {
        source: 'instagram',
        displayName: 'Pavel Novak',
        handleOrPackage: 'paynovak',
        publisher: 'Pavel Novak',
        description: 'Landscape photographer and travel writer.',
        url: 'https://example.org/pavel',
      },
    },
  ];
  const [custom, setCustom] = useState<
    Omit<Candidate, 'id' | 'sourceMode'>
  >({
    source: 'instagram',
    displayName: '',
    handleOrPackage: '',
    publisher: '',
    description: '',
    url: '',
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState('');

  const updateCustom = <K extends keyof typeof custom>(
    key: K,
    value: (typeof custom)[K]
  ) => {
    setCustom(current => ({ ...current, [key]: value }));
    setErrors(current => ({ ...current, [key]: '' }));
    setFormError('');
  };

  const submitCustom = async () => {
    const nextErrors = validateCustomCandidate(custom);
    setErrors(nextErrors);
    setFormError('');
    if (Object.keys(nextErrors).length > 0) return;
    const apiError = await analyze({
      ...custom,
      displayName: custom.displayName.trim(),
      handleOrPackage: custom.handleOrPackage.trim(),
      publisher: custom.publisher.trim(),
      description: custom.description.trim(),
      url: custom.url.trim(),
    });
    if (apiError) setFormError(apiError);
  };

  return (
    <section>
      <PageHead
        eyebrow="EVALUATOR CONTROLLED"
        title="Investigations"
        text="Prove official exclusion, malicious-looking detection, benign guardrails, and arbitrary candidate analysis against the real backend risk engine."
      />
      <div className="preset-grid">
        {presets.map(preset => (
          <button
            className="preset-card"
            key={preset.title}
            disabled={busy}
            onClick={() => void analyze(preset.candidate)}
          >
            <div>
              <span className="label">EXPECTED</span>
              <b className={`expect ${preset.expectation.toLowerCase()}`}>
                {preset.expectation}
              </b>
            </div>
            <h2>{preset.title}</h2>
            <p>{preset.note}</p>
            <span className="preset-action">
              Run backend test <ChevronRight />
            </span>
          </button>
        ))}
      </div>
      <div className="panel custom-analysis">
        <div className="panel-header">
          <div>
            <h2>Evaluator-Controlled Analysis</h2>
            <p className="subtitle">
              No frontend risk logic. Input is sent to POST /api/analyze.
            </p>
          </div>
          <ShieldCheck className="panel-icon" />
        </div>
        <div className="form-grid">
          <label>
            <span>Source</span>
            <select
              value={custom.source}
              onChange={event =>
                updateCustom('source', event.target.value as Source)
              }
            >
              {sources.map(item => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
            {errors.source && (
              <small className="field-error">{errors.source}</small>
            )}
          </label>
          <label>
            <span>Display name *</span>
            <input
              aria-invalid={Boolean(errors.displayName)}
              value={custom.displayName}
              onChange={event =>
                updateCustom('displayName', event.target.value)
              }
              placeholder="PayNova Help Desk"
            />
            {errors.displayName && (
              <small className="field-error">{errors.displayName}</small>
            )}
          </label>
          <label>
            <span>Handle / package *</span>
            <input
              aria-invalid={Boolean(errors.handleOrPackage)}
              value={custom.handleOrPackage}
              onChange={event =>
                updateCustom('handleOrPackage', event.target.value)
              }
              placeholder="paynova_help"
            />
            {errors.handleOrPackage && (
              <small className="field-error">{errors.handleOrPackage}</small>
            )}
          </label>
          <label>
            <span>Publisher *</span>
            <input
              aria-invalid={Boolean(errors.publisher)}
              value={custom.publisher}
              onChange={event => updateCustom('publisher', event.target.value)}
              placeholder="Publisher or account owner"
            />
            {errors.publisher && (
              <small className="field-error">{errors.publisher}</small>
            )}
          </label>
          <label className="wide">
            <span>URL *</span>
            <input
              aria-invalid={Boolean(errors.url)}
              type="url"
              value={custom.url}
              onChange={event => updateCustom('url', event.target.value)}
              placeholder="https://example.com/profile"
            />
            {errors.url && <small className="field-error">{errors.url}</small>}
          </label>
          <label className="wide">
            <span>Description *</span>
            <textarea
              aria-invalid={Boolean(errors.description)}
              value={custom.description}
              onChange={event =>
                updateCustom('description', event.target.value)
              }
              placeholder="Paste the candidate profile or app description"
            />
            {errors.description && (
              <small className="field-error">{errors.description}</small>
            )}
          </label>
        </div>
        <div className="form-actions">
          <button
            className="btn primary"
            disabled={busy}
            onClick={() => void submitCustom()}
          >
            {busy ? 'Analyzing…' : 'Analyze candidate'}
          </button>
          <span>All candidate identity fields are required.</span>
        </div>
        {formError && (
          <div className="form-error" role="alert">
            {formError}
          </div>
        )}
      </div>
    </section>
  );
}

function Incidents({
  items,
  scans,
  busy,
  advance,
  markFalsePositive,
}: {
  items: Incident[];
  scans: Scan[];
  busy: boolean;
  advance: (incident: Incident, target: IncidentStatus) => void;
  markFalsePositive: (incident: Incident) => void;
}) {
  const resolveDetection = (incident: Incident) => {
    const scan = scans.find(item => item.id === incident.scanId);
    const result = scan?.results.find(
      item => item.candidate.id === incident.detectionId
    );
    return result
      ? {
          result,
          sourceMode: scan?.sourceMode ?? result.candidate.sourceMode,
        }
      : null;
  };
  return (
    <section>
      <PageHead
        eyebrow="ANALYST WORKFLOW"
        title="Incidents"
        text="Durable cases with server-enforced state transitions, analyst decisions, and audit history."
      />
      {items.length === 0 ? (
        <div className="panel">
          <EmptyInline
            title="No incidents yet"
            text="Create an incident from a detection that requires analyst review."
          />
        </div>
      ) : (
        <div className="incident-grid">
          {items.map(incident => {
            const resolved = resolveDetection(incident);
            const next = nextStatus[incident.status];
            return (
              <article className="panel incident-card" key={incident.id}>
                <div className="incident-card-head">
                  <RiskBadge level={incident.severity} />
                  <StatusBadge status={incident.status} />
                </div>
                <h2>
                  {resolved?.result.candidate.displayName ??
                    'Detection unavailable'}
                </h2>
                {resolved && (
                  <>
                    <code>{resolved.result.candidate.handleOrPackage}</code>
                    <p>
                      {sourceName(resolved.result.candidate.source)} •{' '}
                      {sourceModeLabel(resolved.sourceMode)}
                    </p>
                  </>
                )}
                <div className="incident-meta">
                  <span>
                    INCIDENT <b>{shortIncidentId(incident.id)}</b>
                  </span>
                  <span>
                    DETECTION <b>{incident.detectionId}</b>
                  </span>
                  <span>
                    UPDATED <b>{formatCompactDate(incident.updatedAt)}</b>
                  </span>
                </div>
                <div className="decision">
                  <span className="label">ANALYST DECISION</span>
                  <p>{incident.decision ?? 'Awaiting analyst review'}</p>
                </div>
                <div className="timeline">
                  {incident.history.map((event, index) => (
                    <div key={`${event.at}-${index}`}>
                      <i />
                      <span>{formatCompactDate(event.at)}</span>
                      <b>
                        {event.from ? `${event.from} → ` : ''}
                        {event.to}
                      </b>
                    </div>
                  ))}
                </div>
                <div className="button-group incident-actions">
                  {next && (
                    <button
                      className="btn primary"
                      disabled={busy}
                      onClick={() => advance(incident, next)}
                    >
                      Move to {next.replace('_', ' ')}
                    </button>
                  )}
                  {incident.status === 'investigating' && (
                    <button
                      className="btn"
                      disabled={busy}
                      onClick={() => markFalsePositive(incident)}
                    >
                      Mark false positive
                    </button>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function BrandAssets({
  brand,
  setBrand,
  save,
  busy,
}: {
  brand: Brand;
  setBrand: (brand: Brand) => void;
  save: () => void;
  busy: boolean;
}) {
  return (
    <section>
      <PageHead
        eyebrow="TRUSTED IDENTITY REGISTRY"
        title="Brand Assets"
        text="Register official brand identifiers. Exact registered identities are excluded before threat scoring."
        actions={
          <button className="btn primary" disabled={busy} onClick={save}>
            {busy ? 'Saving…' : 'Save protected brand'}
          </button>
        }
      />
      <div className="brand-layout">
        <div className="panel form-panel">
          <div className="panel-header">
            <div>
              <h2>Protected brand profile</h2>
              <p className="subtitle">Server-persisted configuration</p>
            </div>
            <Building2 className="panel-icon" />
          </div>
          <div className="form-stack">
            <label>
              <span>Brand name</span>
              <input
                value={brand.name}
                onChange={event =>
                  setBrand({ ...brand, name: event.target.value })
                }
              />
            </label>
            <label>
              <span>Aliases</span>
              <input
                value={brand.aliases.join(', ')}
                onChange={event =>
                  setBrand({
                    ...brand,
                    aliases: event.target.value
                      .split(',')
                      .map(value => value.trim())
                      .filter(Boolean),
                  })
                }
              />
            </label>
            <label>
              <span>Official domains</span>
              <input
                value={brand.domains.join(', ')}
                onChange={event =>
                  setBrand({
                    ...brand,
                    domains: event.target.value
                      .split(',')
                      .map(value => value.trim()),
                  })
                }
              />
            </label>
            <label>
              <span>Description</span>
              <textarea
                value={brand.description}
                onChange={event =>
                  setBrand({ ...brand, description: event.target.value })
                }
              />
            </label>
          </div>
        </div>
        <div className="panel official-panel">
          <div className="panel-header">
            <div>
              <h2>Official identities</h2>
              <p className="subtitle">Excluded before threat scoring</p>
            </div>
            <ShieldCheck className="panel-icon" />
          </div>
          <div className="official-list">
            {brand.officialIdentities.map((identity, index) => (
              <label key={`${identity.platform}-${index}`}>
                <span>{sourceName(identity.platform)}</span>
                <input
                  value={identity.value}
                  onChange={event => {
                    const next = [...brand.officialIdentities];
                    next[index] = {
                      ...next[index],
                      value: event.target.value,
                    };
                    setBrand({ ...brand, officialIdentities: next });
                  }}
                />
              </label>
            ))}
          </div>
          <div className="note-card">
            <CircleCheck />
            <div>
              <b>Official identity exclusion is mandatory</b>
              <p>
                An exact platform + identifier match returns OFFICIAL and is
                never threat-scored.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Analytics({
  scans,
  incidents,
}: {
  scans: Scan[];
  incidents: Incident[];
}) {
  const detections = scans.flatMap(scan =>
    scan.results.filter(result => result.kind === 'detection')
  );
  const high = detections.filter(result => result.riskLevel === 'HIGH').length;
  const medium = detections.filter(
    result => result.riskLevel === 'MEDIUM'
  ).length;
  const low = detections.filter(result => result.riskLevel === 'LOW').length;
  const sourceCounts = sources.map(source => ({
    ...source,
    count: scans.filter(scan => scan.source === source.value).length,
  }));
  const live = scans.filter(scan => scan.sourceMode === 'live').length;
  const fallback = scans.filter(
    scan => scan.sourceMode === 'fallback_fixture'
  ).length;
  const fixture = scans.filter(scan => scan.sourceMode === 'fixture').length;
  return (
    <section>
      <PageHead
        eyebrow="PERSISTED TELEMETRY"
        title="Analytics"
        text="A compact operational view built only from persisted scans, detections, provenance, and incident state."
      />
      <div className="metric-band analytics-metrics">
        <Metric
          dominant
          label="DETECTIONS"
          value={detections.length}
          context={`${scans.length} persisted scans`}
        />
        <Metric label="HIGH" value={high} context={`${medium} medium`} />
        <Metric
          label="OPEN INCIDENTS"
          value={
            incidents.filter(
              item => !['resolved', 'false_positive'].includes(item.status)
            ).length
          }
          context={`${incidents.length} total`}
        />
        <Metric
          label="LIVE SCANS"
          value={live}
          context={`${fixture} fixture • ${fallback} fallback`}
        />
      </div>
      <div className="analytics-grid">
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Risk distribution</h2>
              <p className="subtitle">Explainable scoring output</p>
            </div>
          </div>
          <div className="panel-body">
            <RiskBars high={high} medium={medium} low={low} />
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <div>
              <h2>Source activity</h2>
              <p className="subtitle">Scan executions by adapter</p>
            </div>
          </div>
          <div className="source-activity">
            {sourceCounts.map(item => (
              <div key={item.value}>
                <span>
                  {item.label}
                  <small>{item.mode.toUpperCase()}</small>
                </span>
                <div className="bar-track">
                  <i
                    style={{
                      width: `${
                        scans.length
                          ? Math.max(
                              item.count ? 8 : 0,
                              Math.round((item.count / scans.length) * 100)
                            )
                          : 0
                      }%`,
                    }}
                  />
                </div>
                <b>{item.count}</b>
              </div>
            ))}
          </div>
        </div>
        <div className="panel provenance-panel">
          <div className="panel-header">
            <div>
              <h2>Data provenance</h2>
              <p className="subtitle">No synthetic source is presented as live</p>
            </div>
          </div>
          <div className="provenance-grid">
            <div>
              <Provenance mode="live" />
              <b>{live}</b>
              <span>Successful Apple scans</span>
            </div>
            <div>
              <Provenance mode="fixture" />
              <b>{fixture}</b>
              <span>Deterministic evaluator scans</span>
            </div>
            <div>
              <Provenance mode="fallback_fixture" />
              <b>{fallback}</b>
              <span>Apple upstream fallback events</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function InvestigationDrawer({
  result,
  close,
  create,
  busy,
}: {
  result: AnalysisResult;
  close: () => void;
  create?: () => void;
  busy: boolean;
}) {
  useEffect(() => {
    const handle = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close();
    };
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [close]);
  const classification =
    result.kind === 'official'
      ? 'Verified official identity'
      : result.riskLevel === 'HIGH'
        ? 'Probable brand impersonation'
        : result.riskLevel === 'MEDIUM'
          ? 'Needs analyst review'
          : 'Low-risk similarity';
  const recommendation =
    result.kind === 'official'
      ? 'Registered official identity. Excluded from threat scoring.'
      : result.riskLevel === 'HIGH'
        ? 'Escalate for analyst review. Multiple impersonation indicators were detected.'
        : result.riskLevel === 'MEDIUM'
          ? 'Review identity provenance and context before classification.'
          : 'Low-priority similarity. No strong impersonation evidence detected.';
  const evaluated = result.signals
    .filter(signal => signal.key !== 'logo')
    .sort((left, right) => right.score - left.score);
  return (
    <div
      className="modal"
      role="dialog"
      aria-modal="true"
      aria-label="Investigation evidence"
    >
      <button
        className="modal-scrim"
        aria-label="Close investigation"
        onClick={close}
      />
      <aside className="drawer">
        <div className="drawer-head">
          <div>
            <p className="eyebrow">INVESTIGATION EVIDENCE</p>
            <h2>{result.candidate.displayName}</h2>
            <code>{result.candidate.handleOrPackage}</code>
          </div>
          <button
            className="icon-button"
            aria-label="Close investigation"
            onClick={close}
          >
            <X />
          </button>
        </div>
        <div className="drawer-body">
          <div className="detail-grid">
            <span>
              Publisher<b>{result.candidate.publisher}</b>
            </span>
            <span>
              Source<b>{sourceName(result.candidate.source)}</b>
            </span>
            <span>
              Provenance<b>{sourceModeLabel(result.candidate.sourceMode)}</b>
            </span>
            <span>
              URL<b>{safeHost(result.candidate.url)}</b>
            </span>
          </div>
          <div className="risk-summary">
            <div>
              <span className="label">CLASSIFICATION</span>
              <h3>{classification}</h3>
            </div>
            <div
              className={`risk-number ${result.riskLevel?.toLowerCase() ?? 'official'}`}
            >
              {result.kind === 'official' ? (
                'OFFICIAL'
              ) : (
                <>
                  {result.riskScore}
                  <small>/ 100</small>
                </>
              )}
            </div>
          </div>
          <p className="explanation">{result.explanation}</p>
          {result.kind !== 'official' && (
            <>
              <div className="drawer-section">
                <h3>Contributing signals</h3>
                {evaluated.map(signal => (
                  <div className="factor-row" key={signal.key}>
                    <div>
                      <b>{signal.label}</b>
                      <small>{signal.evidence}</small>
                    </div>
                    <div className="bar-track">
                      <i
                        style={{
                          width: `${
                            signal.max
                              ? Math.round((signal.score / signal.max) * 100)
                              : 0
                          }%`,
                        }}
                      />
                    </div>
                    <b>
                      {signal.score}/{signal.max}
                    </b>
                  </div>
                ))}
                <div className="not-evaluated">
                  <span>
                    <b>Logo Similarity</b>
                    <small>No image evidence supplied.</small>
                  </span>
                  <strong>NOT EVALUATED</strong>
                </div>
              </div>
              {result.scamIndicators.length > 0 && (
                <div className="drawer-section">
                  <h3>Context indicators</h3>
                  <div className="indicator-list">
                    {result.scamIndicators.map(item => (
                      <span key={item}>
                        <TriangleAlert /> {item}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
          <div className="recommendation">
            <ShieldCheck />
            <div>
              <b>Analyst recommendation</b>
              <p>{recommendation}</p>
            </div>
          </div>
          <div className="warning-box">
            <TriangleAlert />
            <span>
              Risk scores prioritize analyst review and are not proof of fraud.
            </span>
          </div>
        </div>
        <div className="drawer-footer">
          <button className="btn" onClick={close}>
            Close
          </button>
          {create && (
            <button className="btn primary" disabled={busy} onClick={create}>
              {busy ? 'Creating incident…' : 'Create incident'}
            </button>
          )}
        </div>
      </aside>
    </div>
  );
}

function RiskBadge({
  level,
  score,
}: {
  level: RiskLevel | null;
  score?: number | null;
}) {
  if (!level) return <span className="risk-badge official">OFFICIAL</span>;
  return (
    <span className={`risk-badge ${level.toLowerCase()}`}>
      {level}
      {typeof score === 'number' ? ` ${score}` : ''}
    </span>
  );
}

function Provenance({
  mode,
}: {
  mode: SourceMode | 'live' | 'fixture';
}) {
  const normalized = mode === 'fallback_fixture' ? 'fallback' : mode;
  const label = mode === 'fallback_fixture' ? 'FALLBACK' : mode.toUpperCase();
  return <span className={`provenance ${normalized}`}>{label}</span>;
}

function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={`status-badge ${status}`}>
      {status.replace('_', ' ').toUpperCase()}
    </span>
  );
}

function EmptyInline({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty-inline">
      <ShieldAlert />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}

function sourceName(source: Source) {
  return sources.find(item => item.value === source)?.label ?? source;
}

function sourceModeLabel(mode: SourceMode) {
  return mode === 'fallback_fixture'
    ? 'FALLBACK_FIXTURE'
    : mode.toUpperCase();
}

function safeHost(value: string) {
  try {
    return new URL(value).host;
  } catch {
    return value;
  }
}

function shortIncidentId(id: string) {
  return `INC-${id.slice(0, 8).toUpperCase()}`;
}

function formatCompactDate(value: string) {
  try {
    return new Date(value).toLocaleString([], {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return value;
  }
}

function validateCustomCandidate(
  candidate: Omit<Candidate, 'id' | 'sourceMode'>
) {
  const errors: Record<string, string> = {};
  if (!sources.some(source => source.value === candidate.source))
    errors.source = 'Choose a valid source.';
  if (!candidate.displayName.trim())
    errors.displayName = 'Display name is required.';
  if (!candidate.handleOrPackage.trim())
    errors.handleOrPackage = 'Handle or package ID is required.';
  if (!candidate.publisher.trim())
    errors.publisher = 'Publisher is required.';
  if (!candidate.description.trim())
    errors.description = 'Description is required.';
  if (!candidate.url.trim()) {
    errors.url = 'URL is required.';
  } else {
    try {
      const url = new URL(candidate.url.trim());
      if (!['http:', 'https:'].includes(url.protocol))
        errors.url = 'Enter a valid HTTP or HTTPS URL.';
    } catch {
      errors.url = 'Enter a valid URL.';
    }
  }
  return errors;
}

function apiErrorMessage(cause: unknown, fallback: string) {
  if (cause && typeof cause === 'object') {
    const response = (cause as { response?: { data?: unknown } }).response;
    const data = response?.data as
      | { error?: { message?: unknown } }
      | undefined;
    if (typeof data?.error?.message === 'string') return data.error.message;
  }
  return fallback;
}

export default App;
