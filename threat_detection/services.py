from .predictor import predict_threat
from .models import ThreatLog
import random

def analyze_traffic(data, ip):
    """Analyze traffic data and create a threat log entry"""
    # Extract features from request data or use defaults
    features = [
        data.get('flow_duration', random.uniform(1, 1000)),
        data.get('total_fwd_packets', random.randint(1, 10)),
        data.get('total_bwd_packets', random.randint(0, 5)),
        data.get('total_len_fwd_packets', random.randint(0, 1000)),
        data.get('total_len_bwd_packets', random.randint(0, 500)),
        data.get('fwd_packet_len_max', random.randint(0, 1500)),
        data.get('fwd_packet_len_min', random.randint(0, 100)),
        data.get('fwd_packet_len_mean', random.randint(0, 750)),
        data.get('fwd_packet_len_std', random.randint(0, 500)),
        data.get('bwd_packet_len_max', random.randint(0, 1500)),
        data.get('bwd_packet_len_min', random.randint(0, 100)),
        data.get('bwd_packet_len_mean', random.randint(0, 750)),
        data.get('bwd_packet_len_std', random.randint(0, 500)),
        data.get('flow_bytes_s', random.uniform(0, 100000)),
        data.get('flow_packets_s', random.uniform(0, 10000)),
        data.get('flow_iat_mean', random.uniform(0, 1000)),
        data.get('flow_iat_std', random.uniform(0, 500)),
        data.get('flow_iat_max', random.uniform(0, 2000)),
        data.get('flow_iat_min', random.uniform(0, 100)),
        data.get('fwd_iat_total', random.uniform(0, 5000)),
        data.get('fwd_iat_mean', random.uniform(0, 1000)),
        data.get('fwd_iat_std', random.uniform(0, 500)),
        data.get('fwd_iat_max', random.uniform(0, 2000)),
        data.get('fwd_iat_min', random.uniform(0, 100)),
        data.get('bwd_iat_total', random.uniform(0, 5000)),
        data.get('bwd_iat_mean', random.uniform(0, 1000)),
        data.get('bwd_iat_std', random.uniform(0, 500)),
        data.get('bwd_iat_max', random.uniform(0, 2000)),
        data.get('bwd_iat_min', random.uniform(0, 100)),
        data.get('fwd_psh_flags', random.randint(0, 10)),
        data.get('bwd_psh_flags', random.randint(0, 10)),
        data.get('fwd_urg_flags', random.randint(0, 5)),
        data.get('bwd_urg_flags', random.randint(0, 5)),
        40, 40,  # Header lengths
        data.get('fwd_packets_s', random.uniform(0, 5000)),
        data.get('bwd_packets_s', random.uniform(0, 5000)),
        data.get('min_packet_len', random.randint(0, 100)),
        data.get('max_packet_len', random.randint(1000, 1500)),
        data.get('packet_len_mean', random.uniform(500, 1000)),
        data.get('packet_len_std', random.uniform(100, 500)),
        0,  # Packet length variance
        data.get('fin_flag_count', random.randint(0, 2)),
        data.get('syn_flag_count', random.randint(0, 2)),
        data.get('rst_flag_count', random.randint(0, 2)),
        data.get('psh_flag_count', random.randint(0, 10)),
        data.get('ack_flag_count', random.randint(0, 20)),
        data.get('urg_flag_count', random.randint(0, 5)),
        0, 0,  # CWE, ECE flags
        data.get('down_up_ratio', random.uniform(0, 5)),
        data.get('avg_packet_size', random.uniform(500, 1200)),
        data.get('avg_fwd_segment_size', random.uniform(500, 1000)),
        data.get('avg_bwd_segment_size', random.uniform(500, 1000)),
        40,  # Fwd header length
        0, 0, 0, 0, 0, 0,  # Bulk features
        data.get('subflow_fwd_packets', random.randint(1, 10)),
        data.get('subflow_fwd_bytes', random.randint(100, 1000)),
        data.get('subflow_bwd_packets', random.randint(0, 5)),
        data.get('subflow_bwd_bytes', random.randint(0, 500)),
        0, 0,  # Window bytes
        0,  # act_data_pkt_fwd
        20,  # min_seg_size_forward
        0, 0, 0, 0,  # Active/Idle features
        0, 0, 0, 0   # More Idle features
    ]

    prediction = predict_threat(features)

    # Create threat log entry
    log = ThreatLog.objects.create(
        source_ip=ip,
        flow_duration=features[0],
        total_packets=features[1] + features[2],
        prediction='ATTACK' if prediction == 1 else 'NORMAL'
    )

    return log

def simulate_dataset():
    """Placeholder for dataset simulation - not used anymore"""
    pass