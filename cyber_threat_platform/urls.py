from django.contrib import admin
from django.urls import path
from threat_detection.views import (
    detect_threat, simulate, dashboard, get_logs,
    get_dashboard_metrics, get_activity_stats, health, get_blocked_ips,
    stop_capture, get_capture_stats, get_capture_sessions
)

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", dashboard, name="dashboard"),
    path("api/health/", health, name="health"),
    path("api/detect/", detect_threat, name="detect_api"),
    path("api/simulate/", simulate, name="simulate_api"),
    path("api/stop-capture/", stop_capture, name="stop_capture"),
    path("api/capture-stats/", get_capture_stats, name="capture_stats"),
    path("api/capture-sessions/", get_capture_sessions, name="capture_sessions"),
    path("api/logs/", get_logs, name="get_logs"),
    path("api/dashboard-metrics/", get_dashboard_metrics, name="dashboard_metrics"),
    path("api/activity-stats/", get_activity_stats, name="activity_stats"),
    path("api/blocked-ips/", get_blocked_ips, name="blocked_ips"),
]
