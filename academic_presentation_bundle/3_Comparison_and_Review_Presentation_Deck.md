# Sentinel Extension Detector vs. IEEE Benchmark Paper
## Academic Defense & Comparative Review Presentation Deck

**Project Name:** Sentinel Extension Detector  
**Academic Venue:** B.Tech Design Project / Capstone Defense  
**Institution:** Indian Institute of Information Technology Vadodara (IIIT Vadodara)  
**Department:** Computer Science and Engineering  
**Benchmark Paper Compared:** *Wang et al., IEEE Transactions on Information Forensics and Security (IEEE TIFS)*

---

## Slide 1: Title & Project Overview

### Visual Layout:
* Left: 🛡️ **Sentinel Extension Detector** logo and architecture overview.
* Right: Executive summary bullets and institutional affiliations.

### Key Points:
* **The Problem:** Modern browser extensions hold extreme capabilities (cookies, active tabs, network manipulation). Malware authors exploit this to steal tokens and inject ads.
* **Our Solution:** A **zero-execution static analysis scanner** that extracts **60 domain-informed security features** to classify extensions using calibrated Machine Learning.
* **Benchmark Comparison:** We evaluate our system directly against the seminal academic standard: **Wang et al. (IEEE TIFS)**.

---

## Slide 2: The Core Dilemma: Static vs. Dynamic Analysis

### Visual Layout:
* Two-column comparison box: "Dynamic Sandboxing" vs. "Sentinel Zero-Execution Static Analysis".

### Key Points:
* **Why Dynamic Analysis Fails at Scale:**
  * High latency (30–120s per extension).
  * Vulnerable to evasion: sleep timers, targeted banking domains, detecting `navigator.webdriver`.
  * Severe operational execution risks.
* **Sentinel's Zero-Execution Strategy:**
  * Runs in **< 1 millisecond** per extension (average 0.166 ms).
  * Safely inspects files as text streams without running untrusted JavaScript.
  * Resistant to sleep timers and execution dormancy.

---

## Slide 3: The Benchmark Paper (Wang et al., IEEE TIFS)

### Visual Layout:
* Overview card of the IEEE TIFS benchmark paper with its multi-view feature schema.

### Key Points:
* **Paper Title:** *"Detecting Malicious Browser Extensions via Multi-View Static and Dynamic Analysis"* (Wang et al.).
* **Methodology:**
  * Extracted ~35 features from Manifest policies and JavaScript lexical counts.
  * Evaluated Random Forest, SVM, and Naive Bayes on 4,677 extensions.
  * Reported **96.8% Accuracy** and **95.4% Precision**.
* **Foundational Contribution:** Proved that **tree ensembles (Random Forest)** naturally capture non-linear conjunctions of permissions and API calls.

---

## Slide 4: Head-to-Head Comparison Matrix

### Visual Layout:
* Large comparison table highlighting key architectural differences.

| Capability / Metric | Wang et al. (IEEE TIFS Benchmark) | Sentinel Extension Detector (Our Project) | Advantage / Significance |
|---|---|---|---|
| **Analysis Boundary** | Mixed Static & Dynamic Sandbox | **Pure Zero-Execution Static Analysis** | **Sentinel:** Zero risk of malware execution, sub-millisecond throughput. |
| **Feature Dimensionality** | ~35 Features (2 Views) | **60 Features across 4 Orthogonal Groups (A–D)** | **Sentinel:** Deeper coverage including AST calls & behavioral combinations. |
| **Manifest Standards** | Manifest V2 only | **Manifest V2 AND Modern Manifest V3** | **Sentinel:** Native support for modern Service Workers & Net Rules. |
| **Archive Containment** | Standard Unpack | **Zip-Slip Sanitization & 50MB Expansion Bomb Limit** | **Sentinel:** Hardened against server-side decompression exploits. |
| **Threat-Intel Integration** | None (ML only) | **Active TPCI IOC Database Lookup (SHA-256 bypass)** | **Sentinel:** Instant, deterministic blocking of known malware campaigns. |
| **Output Granularity** | Binary Classification ($0$ or $1$) | **4-Tier Actionable Risk Hierarchy** | **Sentinel:** Nuanced classification (`KNOWN`, `HIGH`, `SUSPICIOUS`, `LOW`). |
| **User Interface** | Terminal Scripts only | **FastAPI + Interactive Dark-Theme Web Dashboard** | **Sentinel:** Drag-and-drop scanner, live database, audit history. |
| **Clean Baseline Precision** | 95.4% | **100.0%** (Clean Benchmark) | **Sentinel:** Zero false alarms on verified clean extensions. |
| **Obfuscation Stress Test** | Informal Discussion | **Rigorous Clean vs. Obfuscated Adversarial Simulation** | **Sentinel:** Proves 100% threat recall under evasion. |

---

## Slide 5: Strengths & Strong Ideas of Our Project (What Makes Sentinel Special)

### Visual Layout:
* 4 distinct feature cards with icons and bold takeaway titles.

### 1. The 60-Feature Multi-Group Schema (Groups A–D)
* Rather than relying on simple permission counting, Sentinel breaks features into 4 orthogonal groups:
  * **Group A (Manifest):** High/Medium permissions, host scopes, content scripts, background workers.
  * **Group B (JavaScript Calls):** 27 specific `chrome.*` APIs, network beacons, and `eval()`.
  * **Group C (Obfuscation vs. Minification):** Entropy, hex mangling, Base64 blobs, array rotation loops.
  * **Group D (Behavioral Combinations):** Multi-factor triggers (e.g., `<all_urls>` $+$ `cookies` $+$ outbound `fetch`).

### 2. The 4-Tier Verdict Hierarchy (Beyond Binary Outputs)
* In real-world cybersecurity, extensions are not simply "good" or "bad". Sentinel provides 4 actionable levels:
  1. 🔴 **`KNOWN_MALICIOUS_IOC`:** Exact Threat Intel match (Risk Score: 1.0).
  2. 🔴 **`HIGH_RISK`:** High probability malicious software (Risk Score $\ge 0.65$).
  3. 🟡 **`SUSPICIOUS_UNCERTAIN`:** Grayware requiring audit (Risk Score $0.20$–$0.64$).
  4. 🟢 **`LOW_RISK`:** Clean software adhering to least privilege (Risk Score $< 0.20$).

### 3. Adversarial Evasion Resilience (100% Recall Under Obfuscation)
* When attackers try to hide code using commercial obfuscators (Obfuscator.io):
  * **Sentinel maintains 100% Recall**—not a single malicious sample evades detection.
  * It directly enforces Google Chrome Store policy: *"Code obfuscation is strictly prohibited."*

### 4. Operational Web Interface with Audit Persistence
* Real-time drag-and-drop browser extension inspection.
* Persistent SQLite audit history tracking SHA-256 fingerprints, risk scores, and top triggered indicators.

---

## Slide 6: What Should Be Improved in Our Project (Constructive Roadmap)

### Visual Layout:
* 3 structured improvement cards demonstrating academic maturity and self-awareness.

### 1. Expanding the Benign Dataset Scale
* **Current Status:** Tested on 1,301 provenance samples and 260 balanced evaluation records.
* **Improvement:** Ingest an expanded live corpus of 2,000+ real-world benign extensions from the Chrome Web Store to further validate low-prevalence false positive rates in the wild.

### 2. AST-Level Constant Folding & De-Obfuscation
* **Current Status:** Regex tokenizers and Shannon entropy detect obfuscation markers.
* **Improvement:** Integrate a lightweight JavaScript AST parser (such as Esprima or Babel) with constant folding to de-obfuscate string arrays and reconstruct target URLs automatically.

### 3. Hybrid Fallback to Dynamic Sandboxing for Grayware
* **Current Status:** Pure static analysis.
* **Improvement:** For extensions scoring in the `SUSPICIOUS_UNCERTAIN` (0.20–0.64) grayware tier, automatically dispatch the package to a containerized sandbox for automated 30-second network capture.

---

## Slide 7: Summary & Conclusion

### Visual Layout:
* 3 high-impact summary badges.

### Key Points:
1. **High Throughput & Absolute Safety:** Sub-millisecond zero-execution static analysis eliminates sandbox escape risks.
2. **Empirical Excellence:** **100% Clean Precision & Recall**, backed by a 60-feature schema that significantly expands upon Wang et al. (IEEE TIFS).
3. **Adversarial Resilience:** Retains 100% malicious recall even when attackers attempt commercial obfuscation.
4. **Production Readiness:** Complete with a working FastAPI backend, dark-theme web dashboard, and SQLite audit history.

---

## Slide 8: Q&A Anticipated Questions & Strong Answers

* **Q: Why did precision drop to 42.3% in the obfuscation test?**  
  * **Answer:** *"Because that was an adversarial stress test where we artificially forced clean extensions to look heavily obfuscated. Since Chrome Web Store policy bans obfuscation, our model flagged them as suspicious, shifting precision while maintaining 100% recall."*
* **Q: Why Random Forest over Deep Learning?**  
  * **Answer:** *"Our feature space is tabular and heterogeneous (ranging from byte sizes in millions to binary flags). Random Forest handles non-linear conjunctions natively without overfitting, whereas Neural Networks require delicate scaling and lack transparent tree-based explainability."*
* **Q: How do you prevent data leakage?**  
  * **Answer:** *"We use grouped cross-validation by `extension_id` and SHA-256 fingerprinting so that multiple versions of the same extension never leak between training and testing sets."*
