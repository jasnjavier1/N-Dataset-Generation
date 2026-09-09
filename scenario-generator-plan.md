# Scenario Generator Plan (Reusable Framework)

## 1. Core design (build once, reuse everywhere)

| Layer | Purpose | Reusable output |
|---|---|---|
| Canonical Event Schema | One internal format for all generated events | `scenario_id, phase, actor, target, action, outcome, risk, device, network, geo, timestamp, source_type, label` |
| Scenario DSL | Config-driven scenario definitions | Add new scenarios without rewriting engine |
| Temporal Engine | Realistic time distributions and sequencing | Hourly/weekly seasonality, bursts, campaign windows |
| Persona + Baseline Engine | Benign behavior by user/admin/service-account type | Stable “normal” traffic for precision testing |
| Malicious Pattern Library | Threat-specific behaviors (including LOTL mode) | Reusable attack behavior modules |
| Platform Adapters | Convert canonical events into vendor log shapes | Entra/Okta/AD/AWS/Azure/GCP/M365/etc. outputs |
| Ground Truth + Scoring | Labeling and realism QA | Detection coverage, precision/recall, MTTD/MTTR |

## 2. Generator families (plugin model)

Implement each as a plugin with a common interface:

- `identity_abuse`
- `privilege_change`
- `data_discovery`
- `bulk_export`
- `exfil_traffic`
- `endpoint_behavior`
- `persistence_change`
- `defense_control_tamper`
- `cover_activity` (defender-safe)
- `benign_baseline`
- `scenario_orchestrator`
- `ground_truth_labeler`

Each plugin emits canonical events; adapters handle platform-specific logs.

## 3. Time and anomaly model (critical)

1. Generate benign first from persona-specific seasonal models:
   - hour-of-day, day-of-week, holidays, shift schedules, burstiness.
2. Overlay malicious campaigns as sparse, phase-based episodes:
   - recon -> access -> collection -> movement/control.
3. Control ratios at three levels:
   - actor-level (few compromised identities),
   - session-level (few suspicious sessions),
   - event-level (typically 98–99.5% benign overall).
4. LOTL mode constraints:
   - legitimate surfaces only, role-consistent actions, low-and-slow timing,
   - minimal novelty budget (new geo/device/destination),
   - benign-like session flow with subtle scope creep.
5. Cross-source correlation:
   - the same action emits coherent identity/cloud/audit events with shared IDs and close timestamps.

## 4. Open-source + bespoke split

Use open-source packages for simulation foundations (validation, timelines, statistics, serialization, storage).

Build bespoke modules for:

- scenario DSL
- persona models
- malicious pattern logic (including LOTL)
- platform adapters
- ground-truth mapping and realism scoring 

## 5. Execution pipeline

1. Load scenario config + random seed.
2. Build benign timeline for selected tenant profiles.
3. Inject campaign timelines (with optional LOTL mode).
4. Emit canonical events with labels.
5. Transform via adapters into target log formats.
6. Export to files/streams/SIEM test inputs.
7. Run realism checks and fail when outside thresholds.

## 6. Realism gates (must pass)

- Temporal distribution match (hour/day/holiday quantiles)
- Persona behavior consistency
- Cross-log linkage completeness
- Malicious/benign ratio by source and by time slice
- Novelty-rate bounds (device/geo/destination churn)
- Detection replay sanity (expected alerts fire, false positives bounded)

## 7. Generalizing to new scenarios

When adding a new scenario, only add:

1. a new pattern plugin (behavior logic),
2. optional adapter mappings (if a new platform is required),
3. expected-detection mappings in ground truth.

The schema, temporal engine, baseline engine, orchestration, and scoring remain unchanged.
