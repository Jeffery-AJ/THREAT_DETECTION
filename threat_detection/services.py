from .predictor import predict_threat
from .models import ThreatLog
import os
from datetime import datetime
import csv
import random

def analyze_traffic(data, source_ip=None):

    features = [
        data.get("flow_duration", 0),
        data.get("total_packets", 0),
        data.get("packet_length", 0),
        data.get("bytes_per_second", 0),
        data.get("packet_rate", 0),
        data.get("avg_packet_size", 0),
        data.get("connection_count", 0),
        data.get("flag_count", 0)
    ]

    prediction = predict_threat(features)

    attack_type = "ATTACK" if prediction == 1 else "NORMAL"

    log = ThreatLog.objects.create(
        source_ip=source_ip,
        flow_duration=data.get("flow_duration"),
        total_packets=data.get("total_packets"),
        prediction=attack_type
    )
    save_log(source_ip, attack_type)

    return log

def save_log(source_ip, prediction):

    timestamp = datetime.now()

    log_entry = f"{timestamp} | IP: {source_ip} | RESULT: {prediction}\n"

    with open(LOG_FILE, "a") as file:
        file.write(log_entry)


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LOG_FILE = os.path.join(BASE_DIR, "logs", "threat_logs.txt")    

def simulate_dataset():
    dataset_path = os.path.join(BASE_DIR, "Datasets", "sample_attack_data.csv")
    results = []
    
    if not os.path.exists(dataset_path):
        dataset_path = os.path.join(BASE_DIR, "datasets", "sample_attack_data.csv")
        if not os.path.exists(dataset_path):
            return results

    try:
        with open(dataset_path, "r") as f:
            reader = csv.reader(f)
            next(reader)
            count = 0
            for row in reader:
                if count >= 15: 
                    break
                try:
                    data = {
                        "flow_duration": float(row[1]) if row[1] else 0,
                        "total_packets": int(row[2]) + int(row[3]) if row[2] and row[3] else 0,
                        "packet_length": float(row[4]) if row[4] else 0,
                        "bytes_per_second": float(row[14]) if row[14] else 0,
                        "packet_rate": float(row[15]) if row[15] else 0,
                        "avg_packet_size": float(row[53]) if len(row) > 53 and row[53] else 0,
                        "connection_count": 1,
                        "flag_count": int(row[43]) if len(row) > 43 and row[43] else 0,
                    }
                    ip = f"192.168.1.{random.randint(10, 99)}"
                    log = analyze_traffic(data, source_ip=ip)
                    results.append(log)
                    count += 1
                except Exception:
                    pass
    except Exception as e:
        print(f"Error simulating dataset: {e}")
        
    return results