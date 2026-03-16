from django.db import models
import json

class ThreatLog(models.Model):

    source_ip = models.CharField(max_length=50, null=True)

    flow_duration = models.FloatField(null=True)

    total_packets = models.IntegerField(null=True)

    prediction = models.CharField(max_length=20)

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source_ip} - {self.prediction}"


class CaptureSession(models.Model):
    session_id = models.CharField(max_length=100, unique=True)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    total_traffic = models.IntegerField(default=0)
    attacks_detected = models.IntegerField(default=0)
    benign_traffic = models.IntegerField(default=0)
    blocked_ips = models.JSONField(default=list)  # List of blocked IP objects
    duration = models.FloatField(null=True, blank=True)  # Duration in seconds

    def __str__(self):
        return f"Session {self.session_id} - {self.start_time}"

    def save_session_data(self, stats):
        """Save the current stats to this session"""
        self.total_traffic = stats.get('total_traffic', 0)
        self.attacks_detected = stats.get('attacks_detected', 0)
        self.benign_traffic = stats.get('benign_traffic', 0)
        self.blocked_ips = stats.get('blocked_ips', [])
        if self.end_time and self.start_time:
            self.duration = (self.end_time - self.start_time).total_seconds()
        self.save()