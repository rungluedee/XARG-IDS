# Network Attack Detection Backend (CICIDS2017 — Attack Family Classification)

3-Tier pipeline: **Suricata (Tier 1, signatures) → XGBoost Attack-Family classifier (Tier 2, ML) → LLM explainer (Tier 3)**, exposed as a FastAPI backend.

## Unified T1/T2 output schema

Both Tier 1 and Tier 2 emit the **same fields** per flow, so Tier 3 (and the
API response) never has to special-case which tier produced a verdict:

| field | meaning |
|---|---|
| `source` | `"T1"` or `"T2"` |
| `attack_type` | see below |
| `confidence` | 0.0–1.0 (T1: always 1.0 for a firm signature match) |
| `severity_label` | `NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `risk_score` | 0–100 |
| `evidence` | list of short strings backing the verdict |

**`attack_type` vocabulary differs by tier, on purpose:**
- **Tier 2** (ML) can only ever output one of the 9 CICIDS2017 Attack
  Families it was trained on: `BENIGN, DDoS, DoS, PortScan, BruteForce,
  WebAttack, Infiltration, Botnet, Heartbleed`.
- **Tier 1** (Suricata) maps its alert `category`/`signature` text to an
  attack_type using `t1_suricata.py`'s curated table — this can ALSO
  produce `"C2"` (command-and-control/trojan-beacon signatures — CICIDS2017
  has no such label, so only Tier 1 can name it) or `"UNKNOWN"` when the
  alert can't be confidently mapped. **T1 never guesses** — an
  unrecognized category+signature combination always resolves to
  `"UNKNOWN"`, never a plausible-sounding family.

## Routing (unchanged core rule)

A flow Tier 1 matches is recorded **immediately** with its mapped
`attack_type` and full rule evidence, and is **never sent to Tier 2**.
Everything Tier 1 doesn't match goes into the Tier 2 cascade below.
`source` on any single detection is therefore always exactly `"T1"` or
`"T2"`, never both.

## Tier 2 cascade: anomaly detection first, closed-set ML second

A pure closed-set classifier (the original Tier 2) can only ever output a
label it was trained on — a genuinely novel attack (e.g. a custom Hydra
FTP brute-force with different timing than CICIDS2017's own captures) gets
forced into the nearest known class, which is disproportionately `BENIGN`
since that's the training set's majority class. Tier 2 is now a 3-stage
cascade that gates on *deviation from normal*, not *identity match*:

```
unmatched flow
      │
      ▼
Isolation Forest (t2_anomaly_detector.py)     — trained ONLY on BENIGN traffic
      │
      ├─ NOT anomalous ──────────────────────► BENIGN, done
      │                                          (detection_tier="tier2_anomaly_benign")
      └─ anomalous
             │
             ▼
      XGBoost Attack Family model (t2_ml_classifier.py) — advisory 2nd opinion
             │
             ├─ confident (≥ TIER2_ML_CONFIRMATION_THRESHOLD, default 0.85)
             │  and not BENIGN ─────────────────► use it as-is
             │                                      (detection_tier="tier2_ml_confirmed")
             └─ not confident / model unavailable
                    │
                    ▼
             Tier 2.5 Heuristic Triage (t2_5_heuristic_triage.py)
             → tentative "Potential BruteForce" / "Potential DoS" /
               "Potential PortScan" / "Potential C2/Infiltration" /
               "Anomaly - Unclassified" (never a forced specific guess)
                                                   (detection_tier="tier2_5_heuristic")
```

Tier 2.5 looks only at fields already in the 78-column CICIDS2017 feature
vector (destination port, packet rate, SYN/ACK flag counts, flow duration)
plus simple same-capture connection-frequency patterns (repeated hits on
one port, fan-out across many ports from one source) — no new packet
parsing. Every tentative tag is confidence-capped at 0.70 (vs. 1.0 for a
signature match or ≥0.85 for a confirmed ML prediction) so it can never
*look* as certain as a real classification, and evidence is always a list
of the specific signals that fired.

`VerdictRecord` (in `t2_ml_classifier.py`) carries `is_anomaly` and
`anomaly_score` (0–100, from the Isolation Forest) on every flow that
passed through this cascade, regardless of which stage ultimately
resolved it.

## Tier 3 (LLM) — explains, never reclassifies

Tier 3 takes the already-decided verdict (from T1, Tier 2a-confirmed ML,
or Tier 2.5 heuristic triage) and asks an LLM (or, offline, a deterministic
template) to write a short analyst-facing `explanation`. **It cannot
change `attack_type`, `confidence`, `severity_label`, `risk_score`, or
`evidence`** — those fields are copied verbatim from the upstream verdict
before the LLM is ever called, and the LLM's reply is never parsed back
into them (see `_build_flow_result` in `t3_analyzer.py`).

The prompt branches on whether the verdict is **confirmed** (`tier1` /
`tier2_ml_confirmed` — treated as ground truth) or **tentative**
(`tier2_5_heuristic` — including the fully-unclassified case). For
tentative flows, the LLM is explicitly told there is no confirmed category
(or, for a named tentative tag, that it's an unconfirmed heuristic
hypothesis) and instructed to act as a **zero-shot threat profiler**:
reason directly from the raw evidence with hedged language ("is consistent
with", "could indicate"), never assert the tentative label as settled
fact, and never substitute its own guess for a category the pipeline
didn't confidently produce. See `_build_confirmed_prompt` vs.
`_build_tentative_prompt` in `t3_analyzer.py`.

Falls back to an offline templated explanation (with the same
confirmed/tentative distinction) automatically if `ANTHROPIC_API_KEY`
isn't set or the API call fails.

Scope this round: **CICIDS2017 only**. CTU13/C2-Botnet support is a reserved
extension point for next term (see `config.py` / `t2_ml_classifier.py` comments)
— no CTU13 code paths exist yet, and no `C2` class is invented for Tier 2
(CICIDS2017 has none) — though Tier 1 can still name `"C2"` from Suricata
signatures directly, and Tier 2.5 can tentatively flag `"Potential
C2/Infiltration"` from a long-and-slow traffic pattern.

## Attack Families (9 classes)

`BENIGN, DDoS, DoS, PortScan, BruteForce, WebAttack, Infiltration, Botnet, Heartbleed`

Raw-label → family mapping lives in `feature_mapping.py`.

## Pipeline

```
PCAP
 │
 ▼
extractor.py  ── CICFlowMeter → per-flow features (78-col CICIDS2017 schema)
 │
 ▼
t1_suricata.py ── Suricata signature scan (whole file) + alert→attack_type mapping
 │
 ├─ flow matched a signature ──────────────► verdict recorded immediately
 │                                             (source=T1, attack_type, evidence attached)
 │                                             NEVER sent to Tier 2
 └─ flow NOT matched ──────────────────────► Tier 2 cascade (see above):
                                                Isolation Forest → XGBoost (gated) → Tier 2.5
                                                          │  (source=T2, attack_type, evidence,
                                                          │   is_anomaly, anomaly_score)
                                                          ▼
                                              t3_analyzer.py (LLM) explains each verdict
                                              → explanation ONLY; attack_type/confidence/
                                                severity pass through unchanged; prompt
                                                hedges automatically for tentative verdicts
                                              + file_summary (dominant type, distribution)
```

## Project structure

```
backend/
├── main.py                 FastAPI app + pipeline orchestrator + CLI mode
├── config.py                Paths, the strict 78-column feature schema
├── extractor.py              PCAP → flows (real CICFlowMeter only, no fake fallback)
├── t1_suricata.py            Suricata signature scan + alert→attack_type mapping
├── t2_anomaly_detector.py    Tier 2: Isolation Forest, trained on BENIGN-only traffic
├── t2_ml_classifier.py       Tier 2a: XGBoost Attack Family model (confidence-gated 2nd opinion)
├── t2_5_heuristic_triage.py  Tier 2.5: pattern-based tentative tagging on unresolved anomalies
├── train_anomaly_detector.py Training script for t2_anomaly_detector.py's Isolation Forest
├── t2_ml_classifier.py       XGBoost Attack Family classifier
├── risk_scoring.py            Shared severity/risk-score rules (used by BOTH T1 and T2)
├── t3_analyzer.py             Tier 3 LLM: explains verdicts, never reclassifies them
├── train_cicids2017.py       Training script (CICIDS2017 CSV → model_cic.json)
├── feature_mapping.py        Attack-label mapping + CICFlowMeter column-name fixes
├── requirements.txt
├── models/                   model_cic.json + le_cic.pkl (created by training)
├── Dataset/CICIDS2017_CSV/   put your CICIDS2017 CSVs here (not included)
├── uploads/                  uploaded .pcap files land here
├── results/                  saved analysis results (JSON, one per request)
├── tests/                    pytest suite
└── README.md
```

## 1. Install

```bash
python -m venv venv
venv\Scripts\activate            # Windows
# source venv/bin/activate       # Linux/macOS
pip install -r requirements.txt
```

Suricata is a **separate system install** (not pip), optional but recommended:
- Windows: https://suricata.io/download/ → installer, then either add it to
  PATH or set `SURICATA_BIN=C:\Program Files\Suricata\suricata.exe`
- If Suricata isn't installed, Tier 1 auto-disables (logged clearly) and
  every flow flows straight to Tier 2 — the pipeline still runs end-to-end.

## 2. Train the models

Put your CICIDS2017 CSV file(s) in `Dataset/CICIDS2017_CSV/` (the folder is
shipped empty on purpose), then train both Tier 2 models:

```bash
python train_cicids2017.py          # Tier 2a: supervised XGBoost Attack Family model
python train_anomaly_detector.py    # Tier 2: Isolation Forest anomaly baseline
```

**`train_cicids2017.py`** (optional flags: `--data-dir`, `--test-size` default
0.2, `--n-estimators` default 300, `--max-depth` default 8):
1. Load & merge every CSV under `Dataset/CICIDS2017_CSV/`, drop fully-blank rows
2. Map raw labels → the 9 Attack Families, drop unrecognized labels (logged)
3. Build multi-time-window (2s+10s) aggregated features via `time_window.py`
   (mean/max/sum + flow_count per feature, per window)
4. **Chronological** 80/20 split (no shuffling — this is time-series data)
5. Train an XGBoost multiclass model with balanced sample weights
6. Print + save a per-class `classification_report` to `models/train_report.txt`
7. **Validate** feature order and class count (must be exactly 9) before saving
8. Save `models/model_cic.json` + `models/le_cic.pkl` + `models/feature_schema_cic.json`

**`train_anomaly_detector.py`** (optional flags: `--data-dir`,
`--contamination` default 0.01, `--n-estimators` default 200):
1. Loads the same CSVs, filters to **BENIGN-only** rows
2. Fits a `StandardScaler` + `IsolationForest` on the 78-column feature vector
   (no time-windowing — this operates per-flow, matching what `extractor.py`
   produces live)
3. Calibrates the 0–100 `anomaly_score` scale against a held-out slice of
   benign data (1st/99th percentile of `decision_function`), so the scale
   reflects genuine benign variance, not memorized training scores
4. Save `models/anomaly_iso_forest.pkl` + `models/anomaly_scaler.pkl` +
   `models/anomaly_score_bounds.json`

Both are independent — you can run the pipeline with only one trained (Tier 2
cascade degrades gracefully: no XGBoost model just means every anomaly goes
straight to Tier 2.5 heuristic triage instead of getting a confident-family
second opinion first; no Isolation Forest model is a hard `503` since it's
the gate everything else in Tier 2 depends on).

## 3. Run the backend

**As an API server:**
```bash
python main.py
# or: uvicorn main:app --reload
```
Server starts at `http://localhost:8000`. Interactive docs: `http://localhost:8000/docs`.

**As a one-shot CLI (no server needed) — handy for the PCAP smoke test:**
```bash
python main.py --pcap path\to\sample.pcap
```
Prints the same JSON the API would return.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Health check — reports whether the model is trained and whether Suricata is configured |
| POST | `/api/analyze-pcap` | Upload a `.pcap`/`.pcapng` (multipart `file` field), runs the full pipeline |
| GET | `/api/detection-result/{result_id}` | Fetch a previously computed result by id |

`POST /api/analyze-pcap` response shape:
```json
{
  "status": "success",
  "flows": 128,
  "summary": { "total_flows": 128, "dominant_attack_type": "DDoS", "attack_distribution": {"DDoS": 90, "PortScan": 5}, "...": "..." },
  "detections": [ { "flow_id": "...", "source": "T2", "attack_type": "DDoS", "confidence": 0.98, "severity_label": "HIGH", "risk_score": 90, "evidence": ["..."], "explanation": "..." } ],
  "attack_distribution": { "DDoS": 90, "PortScan": 5 },
  "result_id": "a1b2c3d4e5f6"
}
```
On failure (bad pcap, model not trained yet, cicflowmeter missing, ...) you
get `{"status": "error", "message": "..."}` with an appropriate HTTP status
(400/422/503/500) — never a fabricated/fake result.

## 4. Test with a real PCAP

```bash
python main.py --pcap path\to\capture.pcap
```
or via curl once the server is running:
```bash
curl -X POST http://localhost:8000/api/analyze-pcap -F "file=@path/to/capture.pcap"
```

A clean/BENIGN capture should show `flows_matched: 0` under `tier1` and every
flow's verdict coming from Tier 2 (`"source": "T2"`, `attack_family: "BENIGN"`).
A capture containing known attack traffic that matches your Suricata ruleset
should show flows routed to Tier 1 first, with `rule_id`/`rule_category`
populated in the corresponding detections.

## 5. Run the test suite

```bash
pytest tests/ -v
```
- `test_extractor.py` — schema alignment, column-alias fixes, no-fake-data-on-failure (no cicflowmeter/pcap needed)
- `test_t1.py` — eve.json parsing, and that a missing Suricata install never fabricates a match
- `test_api.py` — health check, upload validation, graceful (non-fake) failure when the model isn't trained yet (requires `fastapi`/`xgboost`/`httpx` installed)

## Design notes / hard requirements honored

- **No fake data, anywhere.** `extractor.py` raises `ExtractorError` if
  cicflowmeter is missing or fails — it does not synthesize flows.
  `t1_suricata.py` reports `mode="unavailable"` (never a fabricated match)
  if Suricata isn't installed. `t2_ml_classifier.py` raises
  `ModelNotReadyError` if the trained model is missing — it does not return
  random/stub predictions.
- **Mutually-exclusive T1/T2 routing.** A flow Tier 1 matches is recorded
  immediately with full rule detail and never reaches Tier 2; everything
  else goes to Tier 2. `source` on a detection is therefore always exactly
  `"T1"` or `"T2"`.
- **Feature schema discipline.** `config.cic_feature_columns` is the single
  source of truth, imported by both `train_cicids2017.py` and
  `extractor.py`/`t2_ml_classifier.py` — training and inference cannot
  silently drift apart. `t2_ml_classifier.py` asserts the loaded model's
  feature order matches this list at load time.
- **Known CICFlowMeter naming quirks fixed in `feature_mapping.py`:**
  `CWE Flag Count` (aliased from cicflowmeter's abbreviated name) and
  `Fwd Header Length.1` (a genuine duplicate of `Fwd Header Length` in the
  original CICIDS2017 CSV export — reproduced faithfully, not invented).
