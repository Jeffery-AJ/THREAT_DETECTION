from django.db import models

class ThreatLog(models.Model):

    source_ip = models.CharField(max_length=50, null=True)

    flow_duration = models.FloatField(null=True)

    total_packets = models.IntegerField(null=True)

    prediction = models.CharField(max_length=20)

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.source_ip} - {self.prediction}"