import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from .predictor import predict_threat
import logging
import os
import subprocess
import uuid
from django.utils import timezone
from .models import CaptureSession

# Configure logging
logging.basicConfig(filename='logs/threat_logs.txt', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Flow:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = time.time()
        self.last_time = self.start_time
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_iat = []
        self.bwd_iat = []
        self.fwd_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0}
        self.bwd_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0}
        self.fwd_lengths = []
        self.bwd_lengths = []

    def update(self, pkt, direction):
        current_time = time.time()
        if direction == 'fwd':
            self.fwd_packets += 1
            self.fwd_bytes += len(pkt)
            self.fwd_lengths.append(len(pkt))
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x01: self.fwd_flags['FIN'] += 1
                if flags & 0x02: self.fwd_flags['SYN'] += 1
                if flags & 0x04: self.fwd_flags['RST'] += 1
                if flags & 0x08: self.fwd_flags['PSH'] += 1
                if flags & 0x10: self.fwd_flags['ACK'] += 1
                if flags & 0x20: self.fwd_flags['URG'] += 1
            if self.fwd_packets > 1:
                self.fwd_iat.append(current_time - self.last_time)
        else:
            self.bwd_packets += 1
            self.bwd_bytes += len(pkt)
            self.bwd_lengths.append(len(pkt))
            if TCP in pkt:
                flags = pkt[TCP].flags
                if flags & 0x01: self.bwd_flags['FIN'] += 1
                if flags & 0x02: self.bwd_flags['SYN'] += 1
                if flags & 0x04: self.bwd_flags['RST'] += 1
                if flags & 0x08: self.bwd_flags['PSH'] += 1
                if flags & 0x10: self.bwd_flags['ACK'] += 1
                if flags & 0x20: self.bwd_flags['URG'] += 1
            if self.bwd_packets > 1:
                self.bwd_iat.append(current_time - self.last_time)
        self.last_time = current_time

    def get_features(self):
        duration = self.last_time - self.start_time
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        flow_bytes_s = total_bytes / duration if duration > 0 else 0
        flow_packets_s = total_packets / duration if duration > 0 else 0

        fwd_iat_mean = sum(self.fwd_iat) / len(self.fwd_iat) if self.fwd_iat else 0
        fwd_iat_std = (sum((x - fwd_iat_mean)**2 for x in self.fwd_iat) / len(self.fwd_iat))**0.5 if self.fwd_iat else 0
        fwd_iat_max = max(self.fwd_iat) if self.fwd_iat else 0
        fwd_iat_min = min(self.fwd_iat) if self.fwd_iat else 0

        bwd_iat_mean = sum(self.bwd_iat) / len(self.bwd_iat) if self.bwd_iat else 0
        bwd_iat_std = (sum((x - bwd_iat_mean)**2 for x in self.bwd_iat) / len(self.bwd_iat))**0.5 if self.bwd_iat else 0
        bwd_iat_max = max(self.bwd_iat) if self.bwd_iat else 0
        bwd_iat_min = min(self.bwd_iat) if self.bwd_iat else 0

        fwd_length_mean = sum(self.fwd_lengths) / len(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_length_std = (sum((x - fwd_length_mean)**2 for x in self.fwd_lengths) / len(self.fwd_lengths))**0.5 if self.fwd_lengths else 0
        fwd_length_max = max(self.fwd_lengths) if self.fwd_lengths else 0
        fwd_length_min = min(self.fwd_lengths) if self.fwd_lengths else 0

        bwd_length_mean = sum(self.bwd_lengths) / len(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_length_std = (sum((x - bwd_length_mean)**2 for x in self.bwd_lengths) / len(self.bwd_lengths))**0.5 if self.bwd_lengths else 0
        bwd_length_max = max(self.bwd_lengths) if self.bwd_lengths else 0
        bwd_length_min = min(self.bwd_lengths) if self.bwd_lengths else 0

        # Simplified feature vector (not full 78 features, but enough for basic prediction)
        features = [
            duration,  # Flow Duration
            self.fwd_packets,  # Total Fwd Packets
            self.bwd_packets,  # Total Backward Packets
            self.fwd_bytes,  # Total Length of Fwd Packets
            self.bwd_bytes,  # Total Length of Bwd Packets
            fwd_length_max,  # Fwd Packet Length Max
            fwd_length_min,  # Fwd Packet Length Min
            fwd_length_mean,  # Fwd Packet Length Mean
            fwd_length_std,  # Fwd Packet Length Std
            bwd_length_max,  # Bwd Packet Length Max
            bwd_length_min,  # Bwd Packet Length Min
            bwd_length_mean,  # Bwd Packet Length Mean
            bwd_length_std,  # Bwd Packet Length Std
            flow_bytes_s,  # Flow Bytes/s
            flow_packets_s,  # Flow Packets/s
            fwd_iat_mean,  # Flow IAT Mean
            fwd_iat_std,  # Flow IAT Std
            fwd_iat_max,  # Flow IAT Max
            fwd_iat_min,  # Flow IAT Min
            sum(self.fwd_iat) if self.fwd_iat else 0,  # Fwd IAT Total
            fwd_iat_mean,  # Fwd IAT Mean
            fwd_iat_std,  # Fwd IAT Std
            fwd_iat_max,  # Fwd IAT Max
            fwd_iat_min,  # Fwd IAT Min
            sum(self.bwd_iat) if self.bwd_iat else 0,  # Bwd IAT Total
            bwd_iat_mean,  # Bwd IAT Mean
            bwd_iat_std,  # Bwd IAT Std
            bwd_iat_max,  # Bwd IAT Max
            bwd_iat_min,  # Bwd IAT Min
            self.fwd_flags['PSH'],  # Fwd PSH Flags
            self.bwd_flags['PSH'],  # Bwd PSH Flags
            self.fwd_flags['URG'],  # Fwd URG Flags
            self.bwd_flags['URG'],  # Bwd URG Flags
            40,  # Fwd Header Length (approx)
            40,  # Bwd Header Length (approx)
            self.fwd_packets / duration if duration > 0 else 0,  # Fwd Packets/s
            self.bwd_packets / duration if duration > 0 else 0,  # Bwd Packets/s
            min(self.fwd_lengths + self.bwd_lengths) if self.fwd_lengths + self.bwd_lengths else 0,  # Min Packet Length
            max(self.fwd_lengths + self.bwd_lengths) if self.fwd_lengths + self.bwd_lengths else 0,  # Max Packet Length
            (sum(self.fwd_lengths + self.bwd_lengths) / len(self.fwd_lengths + self.bwd_lengths)) if self.fwd_lengths + self.bwd_lengths else 0,  # Packet Length Mean
            ((sum((x - (sum(self.fwd_lengths + self.bwd_lengths) / len(self.fwd_lengths + self.bwd_lengths)))**2 for x in self.fwd_lengths + self.bwd_lengths) / len(self.fwd_lengths + self.bwd_lengths))**0.5) if self.fwd_lengths + self.bwd_lengths else 0,  # Packet Length Std
            0,  # Packet Length Variance (simplified)
            self.fwd_flags['FIN'],  # FIN Flag Count
            self.fwd_flags['SYN'],  # SYN Flag Count
            self.fwd_flags['RST'],  # RST Flag Count
            self.fwd_flags['PSH'],  # PSH Flag Count
            self.fwd_flags['ACK'],  # ACK Flag Count
            self.fwd_flags['URG'],  # URG Flag Count
            0,  # CWE Flag Count
            0,  # ECE Flag Count
            self.bwd_packets / self.fwd_packets if self.fwd_packets > 0 else 0,  # Down/Up Ratio
            (total_bytes + 40 * total_packets) / total_packets if total_packets > 0 else 0,  # Average Packet Size
            fwd_length_mean,  # Avg Fwd Segment Size
            bwd_length_mean,  # Avg Bwd Segment Size
            40,  # Fwd Header Length.1
            0,  # Fwd Avg Bytes/Bulk
            0,  # Fwd Avg Packets/Bulk
            0,  # Fwd Avg Bulk Rate
            0,  # Bwd Avg Bytes/Bulk
            0,  # Bwd Avg Packets/Bulk
            0,  # Bwd Avg Bulk Rate
            self.fwd_packets,  # Subflow Fwd Packets
            self.fwd_bytes,  # Subflow Fwd Bytes
            self.bwd_packets,  # Subflow Bwd Packets
            self.bwd_bytes,  # Subflow Bwd Bytes
            0,  # Init_Win_bytes_forward
            0,  # Init_Win_bytes_backward
            0,  # act_data_pkt_fwd
            20,  # min_seg_size_forward
            0,  # Active Mean
            0,  # Active Std
            0,  # Active Max
            0,  # Active Min
            0,  # Idle Mean
            0,  # Idle Std
            0,  # Idle Max
            0,  # Idle Min
        ]
        return features

class NetworkMonitor:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.flows = {}
        self.lock = threading.Lock()
        self.monitoring = False
        self.analysis_thread = None
        self.sniff_thread = None
        self.stats = {
            'total_traffic': 0,
            'attacks_detected': 0,
            'benign_traffic': 0,
            'blocked_ips': []
        }
        self.current_session = None
        self._initialized = True

    def packet_callback(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = pkt[IP].proto
            src_port = 0
            dst_port = 0
            if TCP in pkt or UDP in pkt:
                src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            direction = 'fwd' if src_ip < dst_ip else 'bwd'  # Simple direction based on IP comparison

            with self.lock:
                if flow_key not in self.flows:
                    self.flows[flow_key] = Flow(src_ip, dst_ip, src_port, dst_port, protocol)
                self.flows[flow_key].update(pkt, direction)
                self.stats['total_traffic'] += 1

    def analyze_flows(self):
        while self.monitoring:
            time.sleep(10)  # Analyze every 10 seconds
            with self.lock:
                expired_flows = []
                for flow_key, flow in self.flows.items():
                    if time.time() - flow.last_time > 60:  # Expire flows after 60 seconds
                        expired_flows.append(flow_key)
                        features = flow.get_features()
                        prediction = predict_threat(features)
                        if prediction == 1:  # Attack
                            self.block_ip(flow.src_ip, flow_key)
                            self.stats['attacks_detected'] += 1
                            self.stats['blocked_ips'].append({
                                'ip': flow.src_ip,
                                'timestamp': time.time(),
                                'attack_type': 'Detected Attack',
                                'flow_key': str(flow_key)
                            })
                        else:
                            self.stats['benign_traffic'] += 1
                for key in expired_flows:
                    del self.flows[key]

    def block_ip(self, ip, flow_key):
        # Block IP using firewall
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="Block Threat"', 'dir=in', 'action=block', 'remoteip=' + ip], check=True)
            else:  # Linux/Mac
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            logging.info(f"Blocked IP: {ip}, Flow: {flow_key}, Reason: ML Prediction Attack")
        except Exception as e:
            logging.error(f"Failed to block IP {ip}: {e}")

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        # Create new session
        session_id = str(uuid.uuid4())
        self.current_session = CaptureSession.objects.create(
            session_id=session_id,
            start_time=timezone.now()
        )
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self.analyze_flows)
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
        # Start sniffing thread
        self.sniff_thread = threading.Thread(target=self._sniff_packets)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff_packets(self):
        try:
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            logging.error(f"Packet sniffing failed: {e}")

    def stop_monitoring(self):
        self.monitoring = False
        if self.analysis_thread:
            self.analysis_thread.join(timeout=1)
        if self.sniff_thread:
            self.sniff_thread.join(timeout=1)
        # Save session data
        if self.current_session:
            self.current_session.end_time = timezone.now()
            self.current_session.save_session_data(self.stats)
            self.current_session = None

    def get_stats(self):
        return self.stats.copy()

    def reset_stats(self):
        # Save current session data before resetting
        if self.current_session:
            self.current_session.end_time = timezone.now()
            self.current_session.save_session_data(self.stats)
        self.stats = {
            'total_traffic': 0,
            'attacks_detected': 0,
            'benign_traffic': 0,
            'blocked_ips': []
        }

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.start_monitoring()