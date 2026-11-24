"""
LensGuard ML Layer
==================
Lightweight Machine Learning classifier for Prompt Injection detection.
Trained strictly on the public 'deepset/prompt-injections' train split (CC-BY-4.0).
Zero training on evaluation test sets; zero hand-written synthetic training contamination.

Dataset Attribution:
- Dataset: deepset/prompt-injections (Hugging Face)
- License: Creative Commons Attribution 4.0 International (CC-BY-4.0)
- Train size: 546 samples (343 benign, 203 injection)
"""

import os
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "ml_model.joblib"

# Single operating threshold for the ML layer.
# Selected as the dev-set zero-false-positive operating point (T* = 0.72).
# All pipeline components (scan_file, UI, evaluations, and tests) read this constant.
OPERATING_THRESHOLD = 0.72


def _build_pipeline(random_state=42):
    """
    Constructs the feature union (word + char-wb n-grams) and logistic regression.
    Uses fixed random seed for full academic reproducibility.
    """
    union = FeatureUnion([
        ("word_tfidf", TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 3),
            max_features=10000,
            sublinear_tf=True,
            token_pattern=r"(?u)\b\w+\b",
        )),
        ("char_tfidf", TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=10000,
            sublinear_tf=True,
        )),
    ])
    clf = LogisticRegression(
        random_state=random_state,
        max_iter=1000,
    )
    return Pipeline([
        ("features", union),
        ("classifier", clf),
    ])


def train_model(save_path=MODEL_PATH, random_state=42):
    """
    Trains the ML classifier strictly on the deepset/prompt-injections train split.
    No evaluation data, benign files, or test prompts are included.
    """
    from datasets import load_dataset

    print(f"Loading 'deepset/prompt-injections' train split (seed={random_state})...")
    ds = load_dataset("deepset/prompt-injections")
    train_data = ds["train"]

    texts = [str(x["text"]) for x in train_data]
    labels = [int(x["label"]) for x in train_data]

    print(f"Training Logistic Regression pipeline on {len(texts)} samples (Benign: {labels.count(0)}, Injection: {labels.count(1)})...")
    pipeline = _build_pipeline(random_state=random_state)
    pipeline.fit(texts, labels)

    save_path = Path(save_path)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, str(save_path))
    print(f"Model saved -> {save_path}")
    return pipeline


_CACHED_MODEL = None


def get_model(force_retrain=False):
    global _CACHED_MODEL
    if _CACHED_MODEL is not None and not force_retrain:
        return _CACHED_MODEL

    if MODEL_PATH.exists() and not force_retrain:
        try:
            _CACHED_MODEL = joblib.load(str(MODEL_PATH))
            return _CACHED_MODEL
        except Exception:
            pass

    _CACHED_MODEL = train_model()
    return _CACHED_MODEL


def predict_injection(text, threshold=None):
    """
    Evaluates text using the ML classifier.
    Operating decision threshold defaults to OPERATING_THRESHOLD (0.72).
    Scores:
      - prob >= threshold: mapped between 50.0 and 100.0 (triggers firewall threshold >= 15)
      - prob < threshold: mapped between 0.0 and 12.0 (strictly below firewall threshold 15)
    """
    if threshold is None:
        threshold = OPERATING_THRESHOLD

    if not text or not str(text).strip():
        return {
            "score": 0.0,
            "prob": 0.0,
            "threshold": threshold,
            "is_injection": False,
            "label": "BENIGN",
            "model": "deepset_tfidf_logistic_regression",
        }

    model = get_model()
    clean_text = str(text).strip()
    norm_text = clean_text.translate(str.maketrans("013457@$", "oieastas"))

    probs_orig = model.predict_proba([clean_text])[0]
    if norm_text != clean_text:
        probs_norm = model.predict_proba([norm_text])[0]
        prob_injection = max(float(probs_orig[1]), float(probs_norm[1]))
    else:
        prob_injection = float(probs_orig[1])

    # Operating decision boundary: threshold (default 0.72)
    if prob_injection >= threshold:
        scaled_score = 50.0 + ((prob_injection - threshold) / (1.0 - threshold + 1e-9)) * 50.0
        score = min(100.0, round(scaled_score, 1))
        is_inj = True
    else:
        scaled_score = (prob_injection / threshold) * 12.0  # max 12.0 at threshold
        score = max(0.0, round(scaled_score, 1))
        is_inj = False

    return {
        "score": score,
        "prob": round(prob_injection, 4),
        "threshold": threshold,
        "is_injection": is_inj,
        "label": "INJECTION" if is_inj else "BENIGN",
        "model": "deepset_tfidf_logistic_regression",
    }


if __name__ == "__main__":
    train_model(force_retrain=True)
