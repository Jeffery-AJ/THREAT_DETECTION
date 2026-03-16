import pandas as pd
import time
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cyber_threat_platform.settings")
django.setup()

from threat_detection.predictor import predict_threat

data = pd.read_csv("datasets/sample_attack_data.csv")

print("Starting Traffic Simulation...\n")

for index, row in data.iterrows():

    features = row[:-1].tolist()

    prediction = predict_threat(features)

    if prediction == 1:
        print(f"⚠️  Attack Detected at row {index}")
    else:
        print(f"✅ Normal Traffic at row {index}")

    time.sleep(1)