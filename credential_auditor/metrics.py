"""Lightweight Prometheus-compatible metrics.

Zero-dependency implementation. Outputs text/plain in Prometheus exposition format.
Counters, gauges, and histograms are supported via a simple in-memory store.

Example:
    from credential_auditor.metrics import Counter, Gauge, Histogram, render_metrics

    requests = Counter("audit_requests_total", "Total audit requests")
    requests.inc()
    print(render_metrics())  # Prometheus exposition format
"""

from __future__ import annotations

import threading
from typing import Any


class _Metric:
    """Base class for all metrics."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._lock = threading.Lock()


class Counter(_Metric):
    """Monotonically increasing counter."""

    def __init__(self, name: str, help_text: str):
        super().__init__(name, help_text)
        self._value: float = 0.0

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    @property
    def value(self) -> float:
        with self._lock:
            return self._value


class Gauge(_Metric):
    """Value that can go up or down."""

    def __init__(self, name: str, help_text: str):
        super().__init__(name, help_text)
        self._value: float = 0.0

    def set(self, value: float) -> None:
        with self._lock:
            self._value = value

    def inc(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        with self._lock:
            self._value -= amount

    @property
    def value(self) -> float:
        with self._lock:
            return self._value


class Histogram(_Metric):
    """Distribution of values into buckets."""

    DEFAULT_BUCKETS: tuple[float, ...] = (
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    )

    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: tuple[float, ...] = DEFAULT_BUCKETS,
    ):
        super().__init__(name, help_text)
        self.buckets = sorted(buckets)
        self._counts: dict[float, int] = {b: 0 for b in self.buckets}
        self._counts[float("inf")] = 0
        self._sum: float = 0.0
        self._count: int = 0

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum += value
            self._count += 1
            for b in self.buckets:
                if value <= b:
                    self._counts[b] += 1
            self._counts[float("inf")] += 1

    @property
    def count(self) -> int:
        with self._lock:
            return self._count

    @property
    def sum(self) -> float:
        with self._lock:
            return self._sum

    def cumulative_count(self, bucket: float) -> int:
        """Return count of observations <= bucket (cumulative)."""
        with self._lock:
            return self._counts[bucket]


# ── Process-wide registry ─────────────────────────────────────────────────


class _Registry:
    """Process-wide metrics registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._histograms: dict[str, Histogram] = {}

    def counter(self, name: str, help_text: str) -> Counter:
        with self._lock:
            if name not in self._counters:
                self._counters[name] = Counter(name, help_text)
            return self._counters[name]

    def gauge(self, name: str, help_text: str) -> Gauge:
        with self._lock:
            if name not in self._gauges:
                self._gauges[name] = Gauge(name, help_text)
            return self._gauges[name]

    def histogram(self, name: str, help_text: str, buckets: tuple[float, ...] | None = None) -> Histogram:
        with self._lock:
            if name not in self._histograms:
                self._histograms[name] = Histogram(name, help_text, buckets or Histogram.DEFAULT_BUCKETS)
            return self._histograms[name]


REGISTRY = _Registry()


# ── Default metrics for check_please ──────────────────────────────────────


# HTTP/agent broker
HTTP_REQUESTS_TOTAL = REGISTRY.counter(
    "check_please_http_requests_total",
    "Total HTTP requests received by the agent broker",
)
HTTP_REQUESTS_GRANTED = REGISTRY.counter(
    "check_please_http_requests_granted_total",
    "Total credential requests granted (200 OK)",
)
HTTP_REQUESTS_DENIED = REGISTRY.counter(
    "check_please_http_requests_denied_total",
    "Total credential requests denied (403/404)",
)
HTTP_REQUEST_DURATION = REGISTRY.histogram(
    "check_please_http_request_duration_seconds",
    "HTTP request latency in seconds",
)

# Audit pipeline
AUDITS_TOTAL = REGISTRY.counter(
    "check_please_audits_total",
    "Total credential audits executed",
)
KEYS_VALIDATED = REGISTRY.counter(
    "check_please_keys_validated_total",
    "Total keys validated across all audits",
)
KEYS_VALID = REGISTRY.counter(
    "check_please_keys_valid_total",
    "Total keys that returned status=valid",
)
KEYS_FAILED = REGISTRY.counter(
    "check_please_keys_failed_total",
    "Total keys that returned a failing status",
)
AUDIT_DURATION = REGISTRY.histogram(
    "check_please_audit_duration_seconds",
    "Audit run duration in seconds",
)

# Cache
CACHE_HITS = REGISTRY.counter(
    "check_please_cache_hits_total",
    "Total validation cache hits",
)
CACHE_MISSES = REGISTRY.counter(
    "check_please_cache_misses_total",
    "Total validation cache misses",
)
CACHE_SIZE = REGISTRY.gauge(
    "check_please_cache_size",
    "Current number of entries in the validation cache",
)

# Circuit breaker (dynamic — use get_circuit_metrics() to read state)
CIRCUIT_BREAKER_TRIPS = REGISTRY.counter(
    "check_please_circuit_breaker_trips_total",
    "Total times a circuit breaker transitioned to open",
)


def render_metrics() -> str:
    """Render all registered metrics in Prometheus text exposition format."""
    lines: list[str] = []
    for c in REGISTRY._counters.values():
        lines.append(f"# HELP {c.name} {c.help_text}")
        lines.append(f"# TYPE {c.name} counter")
        lines.append(f"{c.name} {c.value}")
    for g in REGISTRY._gauges.values():
        lines.append(f"# HELP {g.name} {g.help_text}")
        lines.append(f"# TYPE {g.name} gauge")
        lines.append(f"{g.name} {g.value}")
    for h in REGISTRY._histograms.values():
        lines.append(f"# HELP {h.name} {h.help_text}")
        lines.append(f"# TYPE {h.name} histogram")
        cumulative = 0
        for bucket in h.buckets:
            cumulative = h.cumulative_count(bucket)
            lines.append(f'{h.name}_bucket{{le="{bucket}"}} {cumulative}')
        lines.append(f'{h.name}_bucket{{le="+Inf"}} {h.cumulative_count(float("inf"))}')
        lines.append(f"{h.name}_sum {h.sum}")
        lines.append(f"{h.name}_count {h.count}")
    return "\n".join(lines) + "\n"
