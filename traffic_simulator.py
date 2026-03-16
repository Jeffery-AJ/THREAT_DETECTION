import pandas as pd
import time
import os
import random
import django
from datetime import datetime

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cyber_threat_platform.settings")
django.setup()

from threat_detection.predictor import predict_threat
from threat_detection.models import ThreatLog

print("Generating Synthetic Traffic with Different Attack Types...\n")

# Function to generate random IP
def generate_random_ip():
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

# Define different attack patterns
attack_patterns = {
    "BENIGN": {
        "Flow Duration": lambda: random.randint(1, 1000),
        "Total Fwd Packets": lambda: random.randint(1, 10),
        "Total Backward Packets": lambda: random.randint(0, 5),
        "Total Length of Fwd Packets": lambda: random.randint(0, 1000),
        "Total Length of Bwd Packets": lambda: random.randint(0, 500),
        "Fwd Packet Length Max": lambda: random.randint(0, 1500),
        "Fwd Packet Length Min": lambda: random.randint(0, 100),
        "Fwd Packet Length Mean": lambda: random.randint(0, 750),
        "Fwd Packet Length Std": lambda: random.randint(0, 500),
        "Bwd Packet Length Max": lambda: random.randint(0, 1500),
        "Bwd Packet Length Min": lambda: random.randint(0, 100),
        "Bwd Packet Length Mean": lambda: random.randint(0, 750),
        "Bwd Packet Length Std": lambda: random.randint(0, 500),
    },
    "DDoS": {
        "Flow Duration": lambda: random.randint(100000, 1000000),
        "Total Fwd Packets": lambda: random.randint(50, 200),
        "Total Backward Packets": lambda: random.randint(0, 10),
        "Total Length of Fwd Packets": lambda: random.randint(5000, 50000),
        "Total Length of Bwd Packets": lambda: random.randint(0, 1000),
        "Fwd Packet Length Max": lambda: random.randint(1000, 1500),
        "Fwd Packet Length Min": lambda: random.randint(500, 1000),
        "Fwd Packet Length Mean": lambda: random.randint(750, 1250),
        "Fwd Packet Length Std": lambda: random.randint(100, 300),
        "Bwd Packet Length Max": lambda: random.randint(0, 500),
        "Bwd Packet Length Min": lambda: random.randint(0, 100),
        "Bwd Packet Length Mean": lambda: random.randint(0, 250),
        "Bwd Packet Length Std": lambda: random.randint(0, 150),
    },
    "Port_Scan": {
        "Flow Duration": lambda: random.randint(1, 100),
        "Total Fwd Packets": lambda: random.randint(1, 5),
        "Total Backward Packets": lambda: random.randint(0, 2),
        "Total Length of Fwd Packets": lambda: random.randint(0, 100),
        "Total Length of Bwd Packets": lambda: random.randint(0, 50),
        "Fwd Packet Length Max": lambda: random.randint(0, 100),
        "Fwd Packet Length Min": lambda: random.randint(0, 50),
        "Fwd Packet Length Mean": lambda: random.randint(0, 50),
        "Fwd Packet Length Std": lambda: random.randint(0, 25),
        "Bwd Packet Length Max": lambda: random.randint(0, 100),
        "Bwd Packet Length Min": lambda: random.randint(0, 50),
        "Bwd Packet Length Mean": lambda: random.randint(0, 50),
        "Bwd Packet Length Std": lambda: random.randint(0, 25),
    },
    "Brute_Force": {
        "Flow Duration": lambda: random.randint(1000, 10000),
        "Total Fwd Packets": lambda: random.randint(10, 50),
        "Total Backward Packets": lambda: random.randint(5, 30),
        "Total Length of Fwd Packets": lambda: random.randint(1000, 10000),
        "Total Length of Bwd Packets": lambda: random.randint(500, 5000),
        "Fwd Packet Length Max": lambda: random.randint(500, 1000),
        "Fwd Packet Length Min": lambda: random.randint(100, 500),
        "Fwd Packet Length Mean": lambda: random.randint(300, 750),
        "Fwd Packet Length Std": lambda: random.randint(50, 200),
        "Bwd Packet Length Max": lambda: random.randint(500, 1000),
        "Bwd Packet Length Min": lambda: random.randint(100, 500),
        "Bwd Packet Length Mean": lambda: random.randint(300, 750),
        "Bwd Packet Length Std": lambda: random.randint(50, 200),
    }
}

# Generate 200 samples: 50 of each type
generated_data = []
for attack_type in attack_patterns:
    for _ in range(50):
        source_ip = generate_random_ip()
        dest_ip = generate_random_ip()
        features = [source_ip, dest_ip]  # Add IPs first
        for i in range(78):  # 78 features
            if i < len(attack_patterns[attack_type]):
                key = list(attack_patterns[attack_type].keys())[i % len(attack_patterns[attack_type])]
                features.append(attack_patterns[attack_type][key]())
            else:
                features.append(random.randint(0, 100))  # Random for remaining features
        features.append(attack_type)  # Add label
        generated_data.append(features)

attack_counts = {}
blocked_ips = set()

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

for i, row in enumerate(generated_data):
    source_ip = row[0]
    dest_ip = row[1]
    features = row[2:-1]  # Skip IPs and label for prediction
    label = row[-1]
    
    prediction = predict_threat(features)
    
    if prediction == 1:
        attack_counts[label] = attack_counts.get(label, 0) + 1
        print(f"⚠️  Attack Detected from {source_ip} - Predicted: ATTACK, Actual: {label}")
        
        # Block the IP
        blocked_ips.add(source_ip)
        print(f"🚫 Blocking IP: {source_ip}")
        
        # Log to database
        ThreatLog.objects.create(
            source_ip=source_ip,
            flow_duration=features[0] if len(features) > 0 else None,
            total_packets=(features[1] + features[2]) if len(features) > 2 else None,
            prediction=label
        )
        
        # Log to blocked IPs file
        with open("logs/blocked_ips.log", "a") as f:
            f.write(f"{datetime.now()}: Blocked {source_ip} - Attack: {label}, Dest: {dest_ip}\n")
    else:
        print(f"✅ Normal Traffic from {source_ip} - Predicted: NORMAL, Actual: {label}")
    
    time.sleep(0.05)

print("\nSimulation Complete!")
print("Attack Types Detected:")
for attack_type, count in sorted(attack_counts.items()):
    print(f"  {attack_type}: {count} instances")

print(f"\nTotal Blocked IPs: {len(blocked_ips)}")
print("Blocked IPs logged to logs/blocked_ips.log")