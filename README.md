# Sentinel Extension — Static Malicious Browser-Extension Detector
> **B.Tech Capstone Project** &middot; Team of 3 &middot; Fully Local Execution &middot; Zero Code Execution &middot; Machine Learning + Heuristic Rules + Threat Intel

Sentinel Extension is a local static-analysis security platform designed to detect malicious Chrome extensions (`.crx`, `.zip`, unpacked directories) without running untrusted code. It combines safe package parsing, strict manifest normalization, threat-intelligence cross-referencing, a 60-feature deterministic numeric pipeline, calibrated machine learning models, and local Tree SHAP explainability into an intuitive 4-page local web dashboard.

---

## 1. Project Overview & Architecture

### High-Level Architecture Flow

```text
[Extension Package (.crx / .zip)]
               │
               ▼
   [1. Safe Extractor Service]
   ├── CRX3/CRX2 header magic & size verification
   ├── Zip-Slip directory traversal blocking ('..', drive letters)
   ├── Decompression bomb prevention (50 MB limit, ratio limits)
   └── Strict temp directory isolation & guaranteed cleanup
               │
               ▼
   [2. Manifest Parser & Threat Intel Match]
   ├── Normalizes Manifest V2 and V3 structures
   ├── Audits API & Host permissions, background workers, CSP unsafe-eval
   └── Exact SHA-256 and Extension ID lookup against SQLite threat-intel catalog
               │
               ▼
   [3. Static Feature Pipeline (60 Features)]
   ├── Group A: Manifest privileges & origin access (17 features)
   ├── Group B: JavaScript AST/regex static analysis & entropy (27 features)
   ├── Group C: Obfuscation vs Minification heuristics (9 features)
   └── Group D: Dangerous behavioral combinations & mismatches (7 features)
               │
               ▼
   [4. Calibrated ML Classifier & Tree SHAP]
   ├── Pre-split leak-free pipelines (imputation + scaling)
   ├── Calibrated probability estimation (Sigmoid / Isotonic)
   ├── Operating alert threshold tuning on validation set
   └── Local feature attribution: top risk-elevating & protective factors
               │
               ▼
   [5. 4-Page Local Web Dashboard & SQLite Audit]
   ├── Overview: Live provenance stats, active detector model card
   ├── Scanner: Upload, risk gauge, SHAP factors, manifest audit, JSON export
   ├── Scan History: Searchable SQLite audit log with details modal & deletion
   └── Evaluation: Confusion matrix, Bayes' prevalence adjustment, bootstrap CIs, ablation
```

---

## 2. Quickstart & Installation

### Prerequisites
- **Python**: 3.12+ (64-bit)
- **OS**: Windows (PowerShell first-class support), Linux, or macOS
- **Browser**: Modern web browser (Chrome, Edge, Firefox)

### Setup Instructions (Windows PowerShell)

```powershell
# 1. Clone / Navigate to repository
cd C:\Users\kakin\.gemini\antigravity\scratch\malicious-extension-detector

# 2. (Optional) Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Run linting & code formatting verification
ruff check .

# 5. Run full automated test suite (70 tests)
pytest -v
```

---

## 3. Running the Local Application

Launch the FastAPI application bound exclusively to `127.0.0.1:8000`:

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open your browser to:
- **Local Web Dashboard**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- **Interactive Swagger API Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check Endpoint**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## 4. Web Dashboard Views

The dashboard is structured into 4 dedicated pages served directly by the FastAPI backend:

1. **Overview Page**:
   - Real-time dataset counts queried live from SQLite (`samples` table).
   - Active detector model card: algorithm name, feature schema version (1.0.0), calibration method, operating alert threshold, and training timestamp.
   - End-to-end security architecture breakdown.

2. **Extension Scanner**:
   - Drag-and-drop file upload supporting `.crx` and `.zip` packages up to 50 MB uncompressed.
   - Real-time progress animation during safe extraction and feature extraction.
   - Transparent verdict banner:
     - `KNOWN_MALICIOUS_IOC` (Matched verified threat intel record)
     - `HIGH_RISK` (Score $\ge$ threshold or $> 0.65$)
     - `SUSPICIOUS_UNCERTAIN` (Intermediate score or elevated privilege profile)
     - `LOW_RISK` (Low model score; accompanied by mandatory non-guarantee caveat)
   - Risk Meter Gauge displaying calibrated probability alongside the operating alert threshold.
   - Local Tree SHAP explainability cards displaying top features driving the score up and protective benign factors.
   - Manifest permissions audit (high-risk badges, broad host origin access, CSP unsafe-eval).
   - One-click JSON audit report download.

3. **Scan History**:
   - Persistent SQLite audit trail of all previous scans (`scan_history` table).
   - Search filter by Extension Name, Extension ID, or SHA-256.
   - Full JSON inspection modal and secure record deletion.

4. **Model Evaluation & Research**:
   - Held-out test performance metrics: Precision, Recall, $F_1$, FPR, FNR, ROC-AUC, PR-AUC, inference latency.
   - Raw confusion matrix ($TN, FP, FN, TP$) with zero metric fabrication.
   - Realistic prevalence adjustment table applying Bayes' theorem to simulate web store base rates ($1.0\%$ and $0.1\%$).
   - 95% bootstrap confidence intervals table ($N=40$ disclosure, empirical percentiles).
   - Feature group ablation progression table (Tiers 1–4).
   - Obfuscation robustness stress test measuring shifts under simulated standard JS obfuscation.
   - Structured False Positive and False Negative error analysis taxonomy.

---

## 5. Command-Line Interface (CLI) Workflows

Sentinel Extension provides dedicated CLI scripts for full end-to-end pipeline automation:

### 1. Dataset Collection & Import
Import threat intelligence records and local packages into SQLite:
```powershell
# Import threat intel records and verify benign matching
python scripts/import_samples.py
```

### 2. Model Training & Calibration
Train models using Protocol A grouped stratified cross-validation, tune operating alert thresholds, calibrate probabilities, and register active detectors:
```powershell
# Train Random Forest with Sigmoid calibration and active registration
python scripts/train_model.py --model random_forest --calibrate sigmoid --register

# Train LightGBM or Logistic Regression baseline
python scripts/train_model.py --model lightgbm --calibrate isotonic
python scripts/train_model.py --model logistic_regression
```

Supported model algorithms in catalog:
- `majority_class` (Baseline)
- `heuristic_rules` (Rule-based baseline)
- `logistic_regression` (Linear $L_2$ regularized)
- `decision_tree` (Interpretable CART)
- `random_forest` (Ensemble bagging, class-weighted)
- `svm` (RBF kernel support vector classifier)
- `lightgbm` (Gradient boosted decision trees)

### 3. Scientific Evaluation & Report Generation
Evaluate the active model against held-out partitions and generate the evaluation report artifact:
```powershell
python scripts/evaluate_models.py
# Serializes report to ml/artifacts/evaluation_report.json
```

---

## 6. Feature Engineering Schema (v1.0.0)

Sentinel Extension extracts **60 deterministic numeric features** organized into 4 distinct tiers:

| Feature Group | Count | Description & Key Indicators |
| :--- | :---: | :--- |
| **Group A: Manifest** | 17 | Manifest version, total permissions, high-risk count (`cookies`, `webRequest`, `proxy`, `management`, `nativeMessaging`), broad host access (`<all_urls>`, `*://*/*`), sensitive host patterns, CSP `'unsafe-eval'`, external update URL. |
| **Group B: JS Static** | 27 | File counts, lines, bytes, line length statistics, sensitive Chrome API calls (`webRequest`, `cookies`, `tabs`, `storage`, `scripting`), dangerous sinks (`eval()`, `Function()`, `setTimeout(string)`), dynamic script injection, external URL references, IP literal count, Shannon entropy of source and string literals. |
| **Group C: Obfuscation** | 9 | Hex-encoded identifiers (`_0x...`), string-array rotation loops, escape sequence density, long base64/hex payload blobs, `atob()` piped into `eval()`, character code concatenation, minification heuristic (`is_minified_heuristic`), and composite `obfuscation_risk_score`. |
| **Group D: Behaviors** | 7 | Over-privilege (declared unused permissions), cookie exfiltration (`cookies` + broad host + networking), redirection hijacking (`webRequestBlocking` + broad host), history surveillance (`tabs`/`history` + networking), remote code execution (fetch + `eval`), form stealing (`dom_inputs` + networking). |

### Minification vs. Obfuscation Separation
Production minifiers (e.g., Terser, Webpack, UglifyJS) produce long single lines and shortened variable names, but do **not** generate hex identifier sequences, string-array extraction loops, or base64 decoding pipes. Sentinel Extension explicitly differentiates minified benign code (`is_minified_heuristic = 1.0`, `obfuscation_risk_score = 0.0`) from adversarial obfuscation to maintain low false positive rates.

---

## 7. Data Leakage Prevention & Splitting Protocols

To prevent data leakage and overly optimistic test results, Sentinel Extension implements strict splitting protocols:

- **Protocol A (Grouped Stratified Split)**: Near-duplicate clusters (identified via normalized source hashing and token Jaccard similarity) and multiple versions of the same extension ID are strictly assigned to the **same partition**. No code variant from a family can leak from training into testing.
- **Protocol B (Chronological Split)**: Evaluates temporal generalizability (trained on historical extensions, evaluated on future releases).
- **Protocol C (Cross-Source Split)**: Tests transferability across independent threat repositories.
- **Pipeline Transformation Safety**: All imputation (`SimpleImputer`) and scaling (`RobustScaler`) are fitted exclusively on training folds via scikit-learn `Pipeline`, guaranteeing zero test-set leakage.

---

## 8. Honest Evaluation & Base-Rate Fallacy

In academic datasets, malware and benign samples are often balanced (e.g., 50% / 50%). However, in real-world browser extension stores, malicious extensions represent **less than 1%** (often $0.1\%$ to $1.0\%$) of all packages.

Sentinel Extension transparently reports expected real-world precision using **Bayes' Theorem**:

$$\text{Precision} = \frac{\text{Recall} \times \pi}{\text{Recall} \times \pi + \text{FPR} \times (1 - \pi)}$$

Where $\pi$ is the real-world prevalence base rate.

### Example Prevalence Sensitivity
- On a balanced evaluation set ($50\%$ malware): Measured Precision $\approx 85\%$.
- At **$1.0\%$ real-world prevalence**: Expected Precision drops to $\approx 15\% - 30\%$ due to false positive volume.
- At **$0.1\%$ real-world prevalence**: Expected Precision drops to $\approx 2\% - 5\%$.

**Sentinel Extension surfaces this warning on every scan and in the evaluation dashboard to prevent over-reliance on raw lab precision.**

---

## 9. Threat Model, Security Guarantees & Limitations

### Security Guarantees
1. **Zero Dynamic Code Execution**: Untrusted JavaScript code is never executed, sandboxed, or interpreted. Inspection is strictly static (AST parsing, regex, entropy calculation, manifest validation).
2. **Path Traversal Resistance**: Rejects any archive entry with `..`, absolute paths, or Windows drive prefixes (`C:`).
3. **Decompression Bomb Protection**: Rejects packages exceeding 50 MB expanded size or anomalous compression ratios ($> 100\times$).
4. **Guaranteed Temp Cleanup**: Extracted files reside in a temporary directory wrapped in a `try...finally` context manager that deletes files immediately upon completion or error.
5. **Zero Local Path Leakage**: Error messages presented to users or returned via the API never disclose server directory paths.
6. **Hardened Localhost Binding**: Application binds strictly to `127.0.0.1:8000` with strict CORS restrictions, Content Security Policy, `X-Frame-Options: DENY`, and `X-Content-Type-Options: nosniff`.

### Known Limitations
- **Delayed Dynamic Execution**: Static analysis cannot inspect JavaScript payloads retrieved dynamically from external command-and-control (C2) servers after installation.
- **Novel Obfuscation**: Highly sophisticated or custom AST-level obfuscation may evade static keyword and pattern heuristics.
- **Over-Privileged Benign Utilities**: Legitimate ad blockers, developer debugging extensions, and network utilities frequently request high-risk permissions (`webRequest`, `<all_urls>`), resulting in elevated heuristic risk scores that require manual review.
- **Low Risk Is Not "Safe"**: A low risk score indicates the absence of detected static anomalies, **not** a certificate of absolute security.

---

## 10. Project Directory Layout

```text
malicious-extension-detector/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py              # API endpoint declarations
│   │   ├── core/
│   │   │   ├── config.py              # Pydantic application settings
│   │   │   └── exceptions.py          # Custom sanitized exceptions
│   │   ├── database/
│   │   │   ├── connection.py          # SQLite connection & schema DDL
│   │   │   └── models.py              # Pydantic DB records
│   │   ├── schemas/
│   │   │   ├── health.py              # Health check schema
│   │   │   ├── manifest.py            # Normalized manifest schema
│   │   │   └── scan.py                # Full scan & overview schemas
│   │   ├── services/
│   │   │   ├── inference_service.py   # Full inference & SHAP explainability
│   │   │   ├── manifest_parser.py     # Safe MV2/MV3 manifest parsing
│   │   │   └── safe_extractor.py      # CRX/ZIP safe unpacker
│   │   └── main.py                    # FastAPI entrypoint with security headers
│   └── tests/
│       ├── test_api.py                # FastAPI endpoints & security headers
│       ├── test_dataset_provenance.py # SQLite, clustering & importers
│       ├── test_evaluation.py         # Bayes theorem, bootstrap, ablation
│       ├── test_feature_extraction.py # Groups A-D & minification
│       ├── test_manifest_parser.py    # MV2/MV3 & CSP parser tests
│       ├── test_safe_extractor.py     # Zip-Slip, bombs, CRX magic
│       ├── test_splits_leakage.py     # Grouped splits & zero-leakage proof
│       └── test_training.py           # Training, calibration & registry security
├── frontend/
│   ├── app.js                         # Vanilla JS dashboard controller
│   ├── index.html                     # 4-page UI layout
│   └── style.css                      # Cybersecurity dark theme
├── ml/
│   ├── artifacts/
│   │   ├── active_model.json          # Active model pointer
│   │   ├── evaluation_report.json     # Serialized evaluation report
│   │   ├── model_card_*.json          # Detailed model metadata
│   │   └── *.joblib                   # Serialized model pipelines
│   ├── collection/
│   │   ├── audit.py                   # Label audit & quality reporting
│   │   ├── benign_matcher.py          # Benign pairing heuristics
│   │   ├── dedup.py                   # Token Jaccard clustering & dedup
│   │   └── importers.py               # Threat intel repository importers
│   ├── datasets/
│   │   ├── dataset_audit.py           # Pre-split distribution audits
│   │   ├── pipeline_factory.py        # Leak-free sklearn pipeline builder
│   │   └── splits.py                  # Grouped stratified splitting
│   ├── evaluation/
│   │   ├── ablation.py                # 4-tier feature group ablation
│   │   ├── bootstrap.py               # 95% bootstrap confidence intervals
│   │   ├── error_analysis.py          # Structured FP/FN failure taxonomy
│   │   ├── metrics.py                 # Core rates, Brier & Bayes prevalence
│   │   └── obfuscation_test.py        # Simulated JS obfuscation stress test
│   ├── features/
│   │   ├── group_a_manifest.py        # Manifest privilege extraction
│   │   ├── group_b_js_static.py       # JavaScript AST, APIs & entropy
│   │   ├── group_c_obfuscation.py     # Obfuscation vs minification
│   │   ├── group_d_behavior.py        # Dangerous behavioral combinations
│   │   ├── pipeline.py                # Unified 60-feature extractor
│   │   └── schema.py                  # Versioned feature schema (1.0.0)
│   └── training/
│       ├── baselines.py               # Heuristic & majority baselines
│       ├── model_registry.py          # Path-confined artifact registry
│       ├── models.py                  # Catalog of ML estimators
│       └── trainer.py                 # Training, tuning & calibration engine
├── scripts/
│   ├── evaluate_models.py             # CLI evaluation suite runner
│   ├── import_samples.py              # CLI threat-intel importer
│   └── train_model.py                 # CLI model training runner
├── pyproject.toml                     # Project dependencies & build metadata
└── README.md                          # Comprehensive documentation
```

---

## 11. Verification & Automated Test Results

The Sentinel Extension codebase is fully tested with **70 automated tests** across all security, ML, and API components:

```powershell
pytest -v
```

```text
======================= 70 passed, 2 warnings in 48.15s =======================
- backend/tests/test_api.py (11 passed): Health, security headers, inference scan, IOC match, Zip-Slip, corrupt packages, overview, history CRUD, evaluation report, index.html.
- backend/tests/test_dataset_provenance.py (8 passed): SQLite schema, provenance tracking, threat intel importers, token Jaccard clustering, label audit.
- backend/tests/test_evaluation.py (7 passed): Bayes theorem prevalence, bounded FPR recall, bootstrap percentiles, ablation progression, obfuscation transforms, error analysis.
- backend/tests/test_feature_extraction.py (8 passed): Schema alignment, Groups A-D extractors, Shannon entropy, minification vs obfuscation, missing value policy.
- backend/tests/test_manifest_parser.py (6 passed): MV2/MV3 normalization, missing/corrupt manifest handling, CSP unsafe-eval detection, update URLs.
- backend/tests/test_safe_extractor.py (16 passed): CRX2/CRX3 headers, Zip-Slip traversal, Windows drive paths, decompression bombs, nesting/file count limits, symlink rejection, temp dir cleanup.
- backend/tests/test_splits_leakage.py (6 passed): Grouped stratified splitting, chronological splitting, zero test-set leakage proof, partition serialization.
- backend/tests/test_training.py (6 passed): Baselines, model catalog, threshold tuning, probability calibration, model registry security & path traversal rejection.
```

---

## 12. License & Academic Attribution

Developed as a B.Tech Capstone Project. Designed exclusively for educational, defensive security auditing, and academic research purposes.
