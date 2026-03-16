from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.shortcuts import render
from .services import analyze_traffic, simulate_dataset
from .models import ThreatLog


def dashboard(request):
    """Serve the main frontend dashboard page."""
    return render(request, "threat_detection/dashboard.html")


@api_view(["GET"])
def health(request):
    return Response({"status": "ok"})


@api_view(["GET"])
def get_logs(request):
    """Return the most recent 100 threat logs as JSON."""
    logs = ThreatLog.objects.order_by("-timestamp")[:100]
    data = [
        {
            "id": log.id,
            "source_ip": log.source_ip or "—",
            "prediction": log.prediction,
            "flow_duration": log.flow_duration,
            "total_packets": log.total_packets,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "",
        }
        for log in logs
    ]
    return Response(data)


@api_view(["POST"])
def detect_threat(request):
    ip = request.META.get("REMOTE_ADDR")
    log = analyze_traffic(request.data, ip)
    return Response({
        "status": "processed",
        "prediction": log.prediction,
        "log_id": log.id,
    })


@api_view(["GET"])
def simulate(request):
    # Run the traffic simulator instead of dataset simulation
    import subprocess
    import os
    
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script_path = os.path.join(BASE_DIR, "traffic_simulator.py")
    
    try:
        # Run the traffic simulator script
        result = subprocess.run(
            ["python", script_path],
            capture_output=True,
            text=True,
            cwd=BASE_DIR,
            timeout=300  # 5 minute timeout
        )
        
        # Count blocked IPs from the log file
        blocked_ips_file = os.path.join(BASE_DIR, "logs", "blocked_ips.log")
        blocked_count = 0
        if os.path.exists(blocked_ips_file):
            with open(blocked_ips_file, "r") as f:
                blocked_count = len(f.readlines())
        
        return Response({
            "status": "success",
            "message": "Traffic simulation completed",
            "blocked_ips": blocked_count,
            "output": result.stdout[-500:] if result.stdout else "",  # Last 500 chars
            "error": result.stderr[-500:] if result.stderr else ""
        })
    except subprocess.TimeoutExpired:
        return Response({
            "status": "timeout",
            "message": "Traffic simulation timed out"
        }, status=408)
    except Exception as e:
        return Response({
            "status": "error",
            "message": f"Traffic simulation failed: {str(e)}"
        }, status=500)


@api_view(["GET"])
def get_blocked_ips(request):
    """Return list of blocked IPs from the log file."""
    import os
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    blocked_ips_file = os.path.join(BASE_DIR, "logs", "blocked_ips.log")
    
    blocked_ips = []
    if os.path.exists(blocked_ips_file):
        with open(blocked_ips_file, "r") as f:
            for line in f:
                # Parse line format: "timestamp: Blocked ip - Attack: type, Dest: dest_ip"
                if ": Blocked " in line:
                    parts = line.split(": Blocked ")
                    if len(parts) == 2:
                        timestamp = parts[0].strip()
                        rest = parts[1].strip()
                        
                        # Extract IP and attack info
                        ip_end = rest.find(" - Attack: ")
                        if ip_end != -1:
                            ip = rest[:ip_end].strip()
                            attack_info = rest[ip_end + 10:].strip()
                            
                            # Parse attack type and destination
                            attack_parts = attack_info.split(", Dest: ")
                            attack_type = attack_parts[0] if attack_parts else "Unknown"
                            destination = attack_parts[1] if len(attack_parts) > 1 else ""
                            
                            blocked_ips.append({
                                "timestamp": timestamp,
                                "ip": ip,
                                "attack_type": attack_type,
                                "destination": destination
                            })
    
    # Return the most recent blocked IPs (last 10)
    return Response({
        "blocked_ips": blocked_ips[-10:][::-1]  # Most recent first
    })

@api_view(["GET"])
def get_dashboard_metrics(request):
    """Return metrics for the dashboard cards."""
    total_logs = ThreatLog.objects.count()
    attacks = ThreatLog.objects.filter(prediction="ATTACK").count()
    blocked_ips = ThreatLog.objects.filter(prediction="ATTACK").values("source_ip").distinct().count()
    
    # Calculate health: 100% minus a penalty for recent attacks
    health = max(0, 100 - (attacks * 2)) 
    
    return Response({
        "totalThreats": attacks,
        "highRiskAlerts": attacks, # Simplified
        "blockedIPs": blocked_ips,
        "systemHealth": health
    })

@api_view(["GET"])
def get_activity_stats(request):
    """Return data for charts."""
    # This is a bit simplified; real implementations would group by time
    # For now, return some distribution based on recent logs
    total_logs = ThreatLog.objects.count()
    attacks = ThreatLog.objects.filter(prediction="ATTACK").count()
    normal = total_logs - attacks
    
    # Dummy distribution data based on simulated values
    return Response({
        "activityData": [
            {"time": "00:00", "requests": 100, "attacks": 5},
            {"time": "04:00", "requests": 150, "attacks": 12},
            {"time": "08:00", "requests": 200, "attacks": 8},
            {"time": "12:00", "requests": 180, "attacks": 15},
            {"time": "16:00", "requests": 220, "attacks": 20},
            {"time": "20:00", "requests": 250, "attacks": 25},
            {"time": "23:59", "requests": total_logs, "attacks": attacks},
        ],
        "threatDistribution": [
            {"name": "Anomalous Traffic", "value": attacks},
            {"name": "Regular Access", "value": normal},
        ],
        "threatFrequency": [
            {"type": "Network Probe", "count": attacks // 2},
            {"type": "Data Infiltration", "count": attacks // 4},
            {"type": "DDoS Attempt", "count": attacks // 4},
        ]
    })