# PayNova Guard V5

PayNova Guard V5 is an evaluator-operable **Digital Risk Protection** platform for HacXLerate 2026 Round One. It combines the polished SOC-style frontend supplied in the project design ZIP with the existing AppDeploy full-stack backend, database persistence, incident workflow, and Apple App Store live integration.

## Product Story

PayNova Guard detects brand impersonation across digital platforms and app stores, explains every risk score, distinguishes registered official assets from suspicious and benign identities, and turns detections into durable analyst incidents. Risk scores are triage signals, not proof of fraud.

## Architecture

```text
React / Vite frontend
        ↓
AppDeploy HTTP API
        ↓
Deterministic explainable detection engine
        ↓
AppDeploy persistent database
        ↓
Source adapters
  • Apple App Store → LIVE
  • Social / Google Play → FIXTURE
```

The production deployment does **not** use `mock-backend.js` or `localStorage` as its backend or persistence layer. The browser-only mock from the design ZIP is design reference material only.

## Main Workspace

The judge-facing navigation is intentionally centered on Digital Risk Protection:

- **Dashboard** — persisted KPIs, risk distribution, source posture, judge flow
- **Monitor** — Apple LIVE and clearly labelled FIXTURE source scans
- **Detections** — search, severity, provenance, and source filters
- **Investigations** — OFFICIAL/HIGH/LOW evaluator presets plus arbitrary custom analysis
- **Incidents** — durable analyst cases with controlled state transitions
- **Brand Assets** — protected brand profile and official identity registry
- **Analytics** — persisted risk/source/provenance telemetry

## Required API Surface

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/api/_healthcheck` | Runtime readiness |
| GET | `/api/state` | Load protected brand, scans, and incidents |
| POST | `/api/brands` | Save protected brand configuration |
| POST | `/api/analyze` | Analyze an evaluator-controlled candidate |
| POST | `/api/scans` | Run Apple LIVE or deterministic FIXTURE scan |
| POST | `/api/incidents` | Create an incident from a detection |
| PUT | `/api/incidents/:id` | Apply a server-enforced incident transition |
| POST | `/api/incidents/:id/false-positive` | Record an explicit false-positive analyst decision |

## Detection Engine

The engine is deterministic and explainable. It uses weighted evidence for:

- name similarity — max 30
- lookalike / homoglyph behavior — max 15
- description similarity — max 15
- publisher mismatch — max 20
- suspicious context and external domains as bounded prioritization signals

A reserved logo signal is **not evaluated** when no image evidence is supplied. The UI deliberately shows `Logo Similarity — NOT EVALUATED` instead of a misleading `0/20`.

Risk thresholds:

- **HIGH:** 70–100
- **MEDIUM:** 40–69
- **LOW:** below 40

Registered exact official identities are excluded before threat scoring. The benign `Pavel Novak / paynovak` preset remains LOW unless stronger suspicious evidence exists.

## Data Provenance

### Apple App Store

Apple is the genuine live source. The backend calls Apple's public search endpoint with a bounded timeout and result count.

- Successful response with results → `LIVE`
- Successful response with zero results → still `LIVE`
- Network/API failure → `FALLBACK_FIXTURE` with a visible warning

### Fixture Sources

Instagram, X/Twitter, Facebook, LinkedIn, YouTube, TikTok, and Google Play currently use deterministic fixture datasets. They are visibly labelled `FIXTURE`; the product does not claim live crawling for them.

## Incident Workflow

```text
NEW → INVESTIGATING → CONFIRMED → RESOLVED
                 ↘ FALSE POSITIVE
```

Transitions are enforced by the backend. Duplicate active incidents for the same detection are rejected. Incident history and false-positive decisions persist in the AppDeploy database.

## Evaluator Demo

A fast judge flow is:

1. Dashboard
2. Investigations → Official PayNova → **OFFICIAL**
3. Investigations → PayNоva Support → **HIGH**
4. Investigations → Pavel Novak → **LOW**
5. Run an arbitrary evaluator-controlled candidate
6. Monitor → Instagram **FIXTURE**
7. Detections → filter HIGH / FIXTURE
8. Inspect evidence and create an incident
9. Move NEW → INVESTIGATING and choose false-positive or confirmed path
10. Refresh to prove persistence
11. Monitor → Apple App Store **LIVE**

## Security / Reliability Scope

The build validates candidate URLs and required fields, keeps backend state server-side, rate-limits analysis and scans, enforces incident transitions on the server, rejects duplicate active incidents, bounds the Apple request, and avoids exposing stack traces. No secret is required for the public Apple Search API.

## Accessibility / Responsive UX

The workspace includes keyboard focus states, a skip link, semantic dialogs, Escape-to-close investigation behavior, aria-live system status, reduced-motion support, text labels in addition to risk colors, and a collapsible mobile navigation pattern.

## Deployment

AppDeploy full-stack deployment is the intended runtime because the application requires frontend hosting, backend HTTP routes, persistent database access, outbound Apple requests, and HTTPS.

Current deployment:

`https://paynova-guard-round-one-eqcmq6.v2.appdeploy.ai/`

## Limitations

- Apple App Store is the only genuine live external source in Round One.
- Social and Google Play adapters are deterministic fixtures.
- Image/logo comparison is not implemented and is not claimed.
- Authentication, tenant isolation, scheduled crawling, automated takedown, WebSockets, custom ML training, and microservices are intentionally outside the Round-One vertical slice.

## Challenge Verification Note

The current project inputs did not include a resolved official Challenge 3 platform URL or a resolved GitHub repository URL. This build therefore follows the supplied PayNova Guard V5 requirements and existing working AppDeploy implementation. Final submission should still be checked against the exact official Challenge 3 acceptance criteria and rulebook before freeze.
