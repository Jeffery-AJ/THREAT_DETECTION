import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "cyber_threat_model.pkl")

import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Suppress the scikit-learn version mismatch warning when loading the model
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

model = joblib.load(MODEL_PATH)



def predict_threat(features):

    features = list(features)
    if len(features) < 78:
        features = features + [0] * (78 - len(features))
    elif len(features) > 78:
        features = features[:78]

    prediction = model.predict([features])

    return prediction[0]
    