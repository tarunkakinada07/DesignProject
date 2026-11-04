"""Baseline classifiers: Majority-class and heuristic rule-based detectors."""

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.dummy import DummyClassifier

from ml.features.schema import ALL_FEATURE_KEYS


class MajorityClassBaseline(BaseEstimator, ClassifierMixin):
    """Majority-class baseline classifier."""

    def __init__(self):
        self._dummy = DummyClassifier(strategy="most_frequent")

    def fit(self, x: np.ndarray, y: np.ndarray):
        self._dummy.fit(x, y)
        self.classes_ = self._dummy.classes_
        return self

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self._dummy.predict(x)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        return self._dummy.predict_proba(x)


class HeuristicRuleBaseline(BaseEstimator, ClassifierMixin):
    """Transparent rule-based baseline using high-risk indicator flags.

    Flags as malicious if any of:
    - flag_cookies_broadhost_network == 1.0
    - flag_webrequest_redirect_broadhost == 1.0
    - flag_remotescript_eval == 1.0
    - perm_count_high_risk >= 3 and has_broad_host_access == 1.0
    - obfuscation_risk_score >= 0.50
    """

    def __init__(self, feature_names: list[str] | None = None):
        self.feature_names = feature_names or ALL_FEATURE_KEYS
        self.classes_ = np.array([0, 1])

    def fit(self, x: np.ndarray, y: np.ndarray):
        # Rule-based model requires no parametric fitting
        return self

    def _evaluate_rules(self, x: np.ndarray) -> np.ndarray:
        n_samples = x.shape[0]
        preds = np.zeros(n_samples, dtype=int)

        name_to_idx = {name: i for i, name in enumerate(self.feature_names)}

        idx_cookies = name_to_idx.get("flag_cookies_broadhost_network")
        idx_redirect = name_to_idx.get("flag_webrequest_redirect_broadhost")
        idx_remote_eval = name_to_idx.get("flag_remotescript_eval")
        idx_high_perms = name_to_idx.get("perm_count_high_risk")
        idx_broad = name_to_idx.get("has_broad_host_access")
        idx_obf = name_to_idx.get("obfuscation_risk_score")

        for i in range(n_samples):
            row = x[i]
            is_mal = False
            if idx_cookies is not None and row[idx_cookies] > 0.0:
                is_mal = True
            elif idx_redirect is not None and row[idx_redirect] > 0.0:
                is_mal = True
            elif idx_remote_eval is not None and row[idx_remote_eval] > 0.0:
                is_mal = True
            elif (
                idx_high_perms is not None
                and idx_broad is not None
                and row[idx_high_perms] >= 3.0
                and row[idx_broad] > 0.0
            ):
                is_mal = True
            elif idx_obf is not None and row[idx_obf] >= 0.50:
                is_mal = True

            preds[i] = 1 if is_mal else 0

        return preds

    def predict(self, x: np.ndarray) -> np.ndarray:
        return self._evaluate_rules(x)

    def predict_proba(self, x: np.ndarray) -> np.ndarray:
        preds = self._evaluate_rules(x)
        probs = np.zeros((len(preds), 2))
        probs[:, 0] = 1.0 - preds * 0.90  # 0.90 confidence when rule fires
        probs[:, 1] = preds * 0.90 + (1.0 - preds) * 0.10
        return probs
