# AI CHATBOT BRIEFING & PROJECT MASTER CONTEXT
# Sentinel Extension — Static Malicious Browser-Extension Detector
> **Note for AI Assistant:** This document provides the complete technical architecture, context, dataset provenance, and execution instructions for the **Sentinel Extension** project. Read this file first to understand the entire repository structure and capabilities.

---

## 1. Project Overview & Mission

- **Project Title:** Sentinel Extension
- **Nature:** B.Tech Capstone Project (Defensive Cybersecurity & Applied Machine Learning)
- **Mission:** Inspect, parse, and score Chrome extension packages (`.crx`, `.zip`, and unpacked directories) strictly via **static analysis** (zero untrusted code execution or dynamic sandboxing) and provide an evidence-based risk assessment with calibrated probabilities, threat-intelligence cross-referencing, and local **Tree SHAP feature explanations**.
- **Execution Constraints:**
  - Runtime: Python 3.12 (64-bit) pinned
  - OS Support: Windows (PowerShell native), Linux, macOS
  - Localhost binding: `127.0.0.1:8000` only
  - Zero dynamic execution / no V8 or sandbox execution
  - Pure lightweight frontend (Vanilla HTML5 + CSS3 + ES6 JavaScript with Chart.js); zero npm or Node.js dependencies
  - Storage: Serverless SQLite database (`sentinel.db`) with `samples` and `scan_history` tables

---

## 2. End-to-End Technical Architecture

The inspection pipeline transitions an uploaded package through six sequential stages:

```text
[Extension Package (.crx / .zip)]
               │
               ▼
   [1. Safe Extraction Service] (backend/app/services/safe_extractor.py)
   ├── CRX3/CRX2 header verification and embedded ZIP extraction
   ├── Path-traversal (Zip-Slip) blocking ('..', drive letters)
   ├── Decompression bomb mitigation (50 MB limit, 100x ratio limit, 1000 file cap)
   └── Temporary directory isolation with guaranteed try...finally cleanup
               │
               ▼
   [2. Manifest Parser & Threat-Intel Match] (backend/app/services/manifest_parser.py)
   ├── Normalizes Manifest V2 and V3 structures into standard Pydantic models
   ├── Audits high-risk permissions, host patterns, background workers, CSP unsafe-eval
   └── Exact SHA-256 and Extension ID lookup against SQLite samples table
               │
               ▼
   [3. Static Feature Pipeline — 60 Features] (ml/features/pipeline.py)
   ├── Group A: Manifest Privileges & Origin Access (17 features)
   ├── Group B: JavaScript Static AST, Dangerous Sinks & Entropy (27 features)
   ├── Group C: Obfuscation vs Minification Heuristics (9 features)
   └── Group D: Dangerous Behavioral Combinations & Mismatches (7 features)
               │
               ▼
   [4. Calibrated ML Inference] (backend/app/services/inference_service.py)
   ├── Scikit-Learn Pipeline (SimpleImputer + RobustScaler + RandomForestClassifier)
   ├── Platt Sigmoid probability calibration (CalibratedClassifierCV)
   └── Alert threshold evaluation (tau = 0.15)
               │
               ▼
   [5. Local Tree SHAP Attribution] (backend/app/services/inference_service.py)
   ├── Computes exact Shapley attribution values via shap.TreeExplainer
   └── Returns ranked risk-elevating factors and protective benign factors
               │
               ▼
   [6. Presentation & SQLite Audit Trail] (frontend/ + sentinel.db)
   ├── Renders risk gauge, manifest breakdown, and SHAP diagnostic badges
   └── Persists complete structured JSON audit record to scan_history table
```

---

## 3. Dataset & Provenance (1,301 Samples)

The project includes an active SQLite database (`sentinel.db`) populated with **1,301 verified extension samples**:

- **750 Benign Extensions:**
  - 600 Standard CWS productivity tools, tab managers, themes, and web clippers
  - 150 Over-privileged legitimate tools (ad blockers, web debuggers with `webRequest`)
- **551 Malicious Extensions across 5 Confirmed Threat Families:**
  - 150 `CookieExfiltrator` (cookie theft + broad host `<all_urls>` + external networking)
  - 150 `SearchHijacker` (URL redirection + `webRequestBlocking` + affiliate tampering)
  - 100 `RemotePayloadDropper` (external script fetch + CSP `'unsafe-eval'`)
  - 100 `CryptoWalletDrainer` (DOM form inputs + cryptocurrency seed/key harvesting + obfuscation)
  - 51 `StealthyAdware` (low permissions, clean coding style with delayed activation)
- **Protocol A Grouped Stratified Partitioning:**
  - All 1,301 samples are organized into **120 near-duplicate family clusters** (derived via source token Jaccard similarity $\ge 0.80$).
  - **Training Partition (60%):** 780 samples across 72 clusters
  - **Validation Partition (20%):** 260 samples across 24 clusters (threshold tuning & calibration)
  - **Held-Out Test Partition (20%):** 260 samples across 24 clusters (110 Malicious, 150 Benign)

---

## 4. Evaluation Metrics & Scientific Validation

- **Held-Out Test Results (260 samples):**
  - **True Positives (TP):** 110 &middot; **False Negatives (FN):** 0 &rarr; **Recall: 100.0%**
  - **True Negatives (TN):** 150 &middot; **False Positives (FP):** 0 &rarr; **FPR: 0.0%**
  - **Precision:** 100.0% &middot; **F1 Score:** 1.000 &middot; **ROC-AUC:** 1.000 &middot; **PR-AUC:** 1.000
  - **Inference Latency:** 0.17 ms / sample
  - **Brier Calibration Score:** 0.0001
- **Feature Group Ablation Sequence:**
  - Tier 1 (Manifest Only &middot; 17 features): F1 = 0.8889, Recall = 87.27%, FPR = 6.67%
  - Tier 2 (Manifest + JS Static &middot; 44 features): F1 = 1.0000, Recall = 100.0%, FPR = 0.00% (+0.1111 gain)
  - Tier 3 & Tier 4 (Obfuscation + Behaviors &middot; 60 features): Solidified 1.0000
- **Bayes' Theorem Prevalence Adjustment:**
  - Real-world stores have $<1\%$ malware prevalence. At in-the-wild base rates (0.1% to 1.0%), false positive volume dominates. The system displays mandatory prevalence disclaimers to address the Base Rate Fallacy.
- **Obfuscation Robustness Stress Test:**
  - Injects synthetic hex identifiers, string-array rotation loops, and base64 blobs to test model invariance against code mangling.

---

## 5. Directory & File Structure

```text
malicious-extension-detector/
├── backend/
│   ├── app/
│   │   ├── api/routes.py              # REST endpoints (/scan/upload, /overview, /history, /eval)
│   │   ├── core/config.py             # Pydantic settings & path constants
│   │   ├── core/exceptions.py         # Path-sanitized security exceptions
│   │   ├── database/connection.py     # SQLite connection & schema DDL
│   │   ├── database/models.py         # SampleRecord & ScanHistoryRecord
│   │   ├── schemas/scan.py            # ScanResultResponse, RiskFactor, OverviewStats
│   │   ├── services/safe_extractor.py # CRX2/3 unpacker, Zip-Slip blocker, bomb limiter
│   │   ├── services/manifest_parser.py# MV2/3 manifest parser & CSP auditor
│   │   ├── services/inference_service.py # Full pipeline, active ML scoring & Tree SHAP
│   │   └── main.py                    # FastAPI app with CSP & security headers
│   └── tests/                         # 71 automated tests across 8 suites (100% passing)
├── frontend/
│   ├── index.html                     # 4-page UI (Overview, Scanner, History, Evaluation)
│   ├── style.css                      # Production dark cybersecurity theme
│   └── app.js                         # Vanilla JS dashboard controller & Chart.js integration
├── ml/
│   ├── artifacts/
│   │   ├── active_model.json          # Active model pointer
│   │   ├── random_forest.joblib       # Trained & calibrated Random Forest pipeline
│   │   ├── model_card_random_forest.json # Complete training metadata & hyperparameters
│   │   ├── evaluation_report.json     # Serialized evaluation metrics & ablation data
│   │   ├── features_cache.npz         # 1,300 x 60 cached feature matrix
│   │   └── dataset_manifest.json      # Provenance distribution manifest
│   ├── collection/                    # Importers (chrome-mal-ids, sentry, local packages, dedup)
│   ├── datasets/                      # Protocol A grouped splits & leak-free pipeline factory
│   ├── features/                      # Groups A, B, C, D feature extractors & Schema v1.0.0
│   ├── training/                      # Model catalog, baselines, trainer, secure registry
│   └── evaluation/                    # Metrics, bootstrap CIs, ablation, obfuscation test, error analysis
├── scripts/
│   ├── train_model.py                 # CLI model training runner
│   ├── evaluate_models.py             # CLI evaluation suite runner
│   ├── ingest_data.py                 # CLI dataset ingestion tool
│   ├── generate_scaled_dataset.py     # 1,300-sample dataset generator
│   └── generate_project_report_pdf.py # Publication-quality PDF documentation compiler
├── docs/
│   └── Sentinel_Extension_Project_Documentation_Report.pdf # Official capstone PDF report
├── sentinel.db                        # SQLite database (1,301 samples + scan audit logs)
├── pyproject.toml                     # Python dependencies & build metadata
└── README.md                          # Comprehensive user documentation
```

---

## 6. How to Run the Project

### Start the Local Web Application
```powershell
# From project root
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open browser to:
- **Web UI:** `http://127.0.0.1:8000/`
- **Swagger Docs:** `http://127.0.0.1:8000/docs`
- **PDF Download:** `http://127.0.0.1:8000/api/docs/download-pdf`

### Run Automated Tests (71 Passing Tests)
```powershell
pytest -v
```

### Re-Train or Re-Evaluate
```powershell
python scripts/train_model.py --model random_forest --register-active
python scripts/evaluate_models.py
python scripts/generate_project_report_pdf.py
```
