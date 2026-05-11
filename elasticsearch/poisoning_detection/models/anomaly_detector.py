import os
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import datetime

def engineer_features(
    df: pd.DataFrame,
    now: datetime.datetime | None = None,
) -> pd.DataFrame:
    if now is None:
        now = datetime.datetime.now()

    feats = pd.DataFrame(index=df.index)

    for col in ['source_confidence', 'source_count', 'ioc_type_weight',
                'cortex_final_score', 'cvss_score', 'actor_danger_score',
                'final_score']:
        if col in df.columns:
            feats[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        else:
            feats[col] = 0.0

    def get_avg_reputation(sources):
        if not isinstance(sources, list) or not sources:
            return 0.0
        reps = [s.get('feed_reputation', 0) for s in sources if isinstance(s, dict)]
        return sum(reps) / len(reps) if reps else 0.0

    if 'sources' in df.columns:
        feats['avg_feed_reputation'] = df['sources'].apply(get_avg_reputation)
    else:
        feats['avg_feed_reputation'] = 0.0

    if 'enriched' in df.columns:
        expanded_enriched = df['enriched'].apply(lambda x: x if isinstance(x, dict) else {})
        feats['mitre_technique_count'] = pd.to_numeric(
            expanded_enriched.apply(lambda x: (x.get('mitre') or {}).get('technique_count', 0)),
            errors='coerce'
        ).fillna(0)

        feats['mitre_tactic_count'] = pd.to_numeric(
            expanded_enriched.apply(lambda x: (x.get('mitre') or {}).get('tactic_count', 0)),
            errors='coerce'
        ).fillna(0)

        feats['is_default_technique'] = expanded_enriched.apply(
            lambda x: 1 if (x.get('mitre') or {}).get('is_default', True) else 0
        ).astype(float)

        feats['enriched_score'] = pd.to_numeric(
            expanded_enriched.apply(lambda x: x.get('score', {}).get('enriched_score', 0)),
            errors='coerce'
        ).fillna(0)

        tc = feats['mitre_technique_count']
        ta = feats['mitre_tactic_count'].clip(lower=1)
        feats['technique_tactic_ratio'] = (tc / ta).fillna(0)

    else:
        feats['mitre_technique_count']  = 0
        feats['mitre_tactic_count']     = 0
        feats['is_default_technique']   = 1.0 
        feats['enriched_score']         = 0
        feats['technique_tactic_ratio'] = 0

    if 'source_names' in df.columns:
        feats['source_names_count'] = df['source_names'].apply(
            lambda x: len(x) if isinstance(x, list) else (1 if isinstance(x, str) and x else 0)
        )
    else:
        feats['source_names_count'] = 0

    def get_age_days(first_seen):
        if not first_seen or pd.isna(first_seen):
            return 0
        try:
            dt = pd.to_datetime(first_seen)
            return (now - dt.replace(tzinfo=None)).days
        except Exception:
            return 0

    if 'first_seen' in df.columns:
        feats['infrastructure_age_days'] = df['first_seen'].apply(get_age_days)
    else:
        feats['infrastructure_age_days'] = 0

    return feats

class AnomalyDetector:
    def __init__(self, random_state=42, contamination=None, n_estimators=200, model_dir="models/"):
        self.random_state  = random_state
        env_cont           = os.getenv("CONTAMINATION_MAX")
        self.contamination = (
            contamination if contamination is not None
            else (float(env_cont) if env_cont else 0.05)
        )
        self.n_estimators   = n_estimators
        self.model_dir      = model_dir
        self.model          = None
        self.scaler         = None
        self.feature_names  = None
        self.score_mean     = 0.0
        self.score_std      = 1.0
        self.score_threshold = 0.0

    def train(self, records):
        df       = pd.DataFrame(records)
        features = engineer_features(df, now=datetime.datetime.now())

        self.scaler = StandardScaler()
        X           = self.scaler.fit_transform(features)

        self.model = IsolationForest(
            n_estimators  = self.n_estimators,
            contamination = self.contamination,
            random_state  = self.random_state,
            n_jobs        = -1,
        )
        self.model.fit(X)
        self.feature_names = list(features.columns)

        train_scores         = self.model.decision_function(X)
        self.score_mean      = float(np.mean(train_scores))
        self.score_std       = float(np.std(train_scores)) if float(np.std(train_scores)) > 1e-9 else 1.0
        self.score_threshold = float(np.quantile(train_scores, self.contamination))
        return self

    def predict(self, records):
        if not self.model or not self.scaler:
            raise ValueError("Model not trained or loaded.")

        df       = pd.DataFrame(records)
        features = engineer_features(df, now=datetime.datetime.now())

        features   = features[self.feature_names]
        X          = self.scaler.transform(features)
        raw_scores = self.model.decision_function(X)

        z             = (raw_scores - self.score_threshold) / max(self.score_std, 1e-9)
        anomaly_scores = 1.0 / (1.0 + np.exp(z))
        pred_binary   = (raw_scores < self.score_threshold).astype(int)

        results = []
        for i, rec in enumerate(records):
            enriched = dict(rec)
            enriched["ml_score"]             = float(anomaly_scores[i])
            enriched["poisoning_flagged"]    = bool(pred_binary[i])
            enriched["infrastructure_age_days"] = int(features["infrastructure_age_days"].iloc[i])
            if bool(pred_binary[i]) and not enriched.get("poison_strategy"):
                enriched["poison_strategy"] = "ml_detected"
            results.append(enriched)

        return results

    def save(self, path=None):
        path = path or self.model_dir
        os.makedirs(path, exist_ok=True)
        joblib.dump(self.model,         os.path.join(path, "isolation_forest.pkl"))
        joblib.dump(self.scaler,        os.path.join(path, "scaler.pkl"))
        joblib.dump(self.feature_names, os.path.join(path, "feature_names.pkl"))
        calibration = {
            "score_mean":      self.score_mean,
            "score_std":       self.score_std,
            "score_threshold": self.score_threshold,
            "contamination":   self.contamination,
        }
        joblib.dump(calibration, os.path.join(path, "score_calibration.pkl"))
        print(f" Model saved to {path}")

    def load(self, path=None):
        path = path or self.model_dir
        self.model         = joblib.load(os.path.join(path, "isolation_forest.pkl"))
        self.scaler        = joblib.load(os.path.join(path, "scaler.pkl"))
        self.feature_names = joblib.load(os.path.join(path, "feature_names.pkl"))

        calibration_path = os.path.join(path, "score_calibration.pkl")
        if os.path.exists(calibration_path):
            calibration          = joblib.load(calibration_path)
            self.score_mean      = float(calibration.get("score_mean",      0.0))
            self.score_std       = max(float(calibration.get("score_std",   1.0)), 1e-9)
            self.score_threshold = float(calibration.get("score_threshold", 0.0))
            self.contamination   = float(calibration.get("contamination", self.contamination))
        else:
            self.score_mean      = 0.0
            self.score_std       = 1.0
            self.score_threshold = 0.0

        _THRESHOLD_WARN_BOUND = 1.0
        if not (-_THRESHOLD_WARN_BOUND <= self.score_threshold <= _THRESHOLD_WARN_BOUND):
            import warnings
            warnings.warn(
                f"Loaded score_threshold={self.score_threshold:.4f} is outside the expected "
                f"range [{-_THRESHOLD_WARN_BOUND}, {_THRESHOLD_WARN_BOUND}].  The calibration "
                "artefact may be stale or from a different model — verify before using in production.",
                UserWarning,
                stacklevel=2,
            )

        print(f" Model loaded from {path}")
        return self
