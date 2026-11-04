"""Model catalog and factory defining the progression of detectors."""

import lightgbm as lgb
from sklearn.base import BaseEstimator
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from ml.datasets.pipeline_factory import build_training_pipeline
from ml.training.baselines import HeuristicRuleBaseline, MajorityClassBaseline


def get_model_catalog(seed: int = 42) -> dict[str, BaseEstimator]:
    """Return dictionary of candidate models ordered by complexity progression.

    Progression:
    1. Majority-class baseline
    2. Transparent heuristic rule baseline
    3. Scaled Logistic Regression
    4. Decision Tree
    5. Random Forest
    6. Support Vector Machine (SVM)
    7. LightGBM Gradient Boosting
    """
    catalog = {
        "majority_baseline": MajorityClassBaseline(),
        "heuristic_rule": HeuristicRuleBaseline(),
        "logistic_regression": build_training_pipeline(
            LogisticRegression(class_weight="balanced", random_state=seed, max_iter=1000),
            with_scaling=True,
            with_imputer=True,
        ),
        "decision_tree": build_training_pipeline(
            DecisionTreeClassifier(class_weight="balanced", max_depth=6, random_state=seed),
            with_scaling=False,
            with_imputer=True,
        ),
        "random_forest": build_training_pipeline(
            RandomForestClassifier(
                n_estimators=100, class_weight="balanced", random_state=seed, n_jobs=-1
            ),
            with_scaling=False,
            with_imputer=True,
        ),
        "svm": build_training_pipeline(
            SVC(probability=True, class_weight="balanced", random_state=seed),
            with_scaling=True,
            with_imputer=True,
        ),
        "lightgbm": build_training_pipeline(
            lgb.LGBMClassifier(
                class_weight="balanced",
                random_state=seed,
                n_estimators=100,
                verbose=-1,
                n_jobs=-1,
            ),
            with_scaling=False,
            with_imputer=True,
        ),
    }
    return catalog
