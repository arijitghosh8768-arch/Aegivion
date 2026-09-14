from prometheus_client import Counter, Histogram

api_requests_total = Counter(
    "api_requests_total",
    "Total count of API requests",
    ["method", "endpoint"]
)

ai_requests_total = Counter(
    "ai_requests_total",
    "Total count of AI requests"
)

scans_total = Counter(
    "scans_total",
    "Total count of scans"
)

api_request_duration_seconds = Histogram(
    "api_request_duration_seconds",
    "Histogram of API request duration",
    ["method", "endpoint"]
)

ai_request_duration_seconds = Histogram(
    "ai_request_duration_seconds",
    "Histogram of AI request duration"
)
