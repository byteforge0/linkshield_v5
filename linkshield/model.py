import os
import joblib
import numpy as np
from .features import feature_vector

MODEL_PATH = os.path.join("models", "linkshield_model.joblib")

def load_model(path=MODEL_PATH):
    if not os.path.exists(path):
        return None
    return joblib.load(path)

def predict(url, model=None):
    if model is None:
        model = load_model()
    if model is None:
        return None, None
    x = np.array([feature_vector(url)])
    label = int(model.predict(x)[0])
    probability = float(model.predict_proba(x)[0][1]) if hasattr(model, "predict_proba") else float(label)
    return label, probability

