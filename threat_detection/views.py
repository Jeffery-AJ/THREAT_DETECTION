from rest_framework.decorators import api_view
from rest_framework.response import Response
from .services import analyze_traffic, simulate_dataset

@api_view(["POST"])
def detect_threat(request):

    ip = request.META.get("REMOTE_ADDR")

    log = analyze_traffic(request.data, ip)

    return Response({
        "status": "processed",
        "prediction": log.prediction,
        "log_id": log.id
    })
@api_view(["GET"])
def simulate(request):

    results = simulate_dataset()

    return Response({
        "samples_processed": len(results)
    })      