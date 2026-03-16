from __future__ import annotations

import os
from typing import Iterable, Optional

try:
    import joblib  # type: ignore
except Exception:  # pragma: no cover
    joblib = None  # type: ignore

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "cyber_threat_model.pkl")


def _load_model():
    """
    Best-effort model loader.

    This project is often run in environments where scikit-learn wheels are not
    available, so we allow the web app to run with a heuristic fallback.
    """
    if joblib is None:
        return None
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


_MODEL = None

def _get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = _load_model()
    return _MODEL



def predict_threat(features: Iterable[float | int]) -> int:
    """
    Return 1 for ATTACK, 0 for NORMAL.
    """
    vector = list(features)
    if len(vector) < 78:
        vector = vector + [0] * (78 - len(vector))
    elif len(vector) > 78:
        vector = vector[:78]

    model = _get_model()
    if model is not None:
        try:
            prediction = model.predict([vector])
            return int(prediction[0])
        except Exception:
            # Fall through to heuristic if model inference fails
            pass

    # Heuristic fallback: treat high packet rate / flag count as suspicious.
    # indices correspond to threat_detection/services.py feature ordering
    flow_duration = float(vector[0] or 0)
    total_packets = float(vector[1] or 0)
    packet_rate = float(vector[4] or 0)
    flag_count = float(vector[7] or 0)

    score = 0.0
    score += min(total_packets / 500.0, 2.0)
    score += min(packet_rate / 200.0, 2.0)
    score += min(flag_count / 50.0, 2.0)
    score += 0.5 if flow_duration > 60_000 else 0.0

    return 1 if score >= 3.0 else 0
    