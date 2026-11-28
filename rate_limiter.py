from __future__ import annotations
"""
速率限制器

配置 res/{port_api}/config.json ，示例如下：
{
    "rate_limits": {
        "default":           {"requests": 60,  "range": 60},
        "/auth/register":    {"requests": 5,   "range": 300},
        "/file/upload_file": {"requests": 20,  "range": 60}
    }
}

- requests : 在 range 秒内允许的最大请求数
- range    : 时间窗口，单位为秒
- default  : 对未单独配置的 API 生效；若不设置则不限速

"""

import math
import logging
import time
import threading
from collections import deque


def parse_limits(raw):
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("rate_limits must be an object")
    limits = {}
    for endpoint, rule in raw.items():
        if endpoint != "default" and not (isinstance(endpoint, str) and endpoint.startswith("/")):
            raise ValueError("invalid endpoint in rate_limits")
        if not isinstance(rule, dict):
            raise ValueError(f"{endpoint}: expected a rate limit object")
        requests = rule.get("requests")
        window = rule.get("range")
        if type(requests) is not int or requests < 0:
            raise ValueError(f"{endpoint}: requests must be a nonnegative integer")
        try:
            window = float(window) if not isinstance(window, bool) else 0
        except (TypeError, ValueError, OverflowError):
            window = 0
        if not math.isfinite(window) or window <= 0:
            raise ValueError(f"{endpoint}: range must be positive and finite")
        limits[endpoint] = (requests, window)
    return limits


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._requests = {}
        self._limits = {}
        self._raw_limits = None
        self._start_cleanup()

    def _start_cleanup(self):
        def _loop():
            while True:
                time.sleep(300)
                self._cleanup()
        t = threading.Thread(target=_loop, daemon=True, name="tfv5-ratelimit-gc")
        t.start()

    def _cleanup(self):
        with self._lock:
            max_range = max((window for _, window in self._limits.values()), default=60)
            cutoff = time.monotonic() - max_range
            expired = [key for key, hits in self._requests.items() if hits[-1] <= cutoff]
            for k in expired:
                del self._requests[k]

    def configure(self, raw_limits):
        """Reload changed settings, keeping the previous policy on invalid edits."""
        with self._lock:
            if raw_limits is self._raw_limits:
                return
            self._raw_limits = raw_limits
            try:
                self._limits = parse_limits(raw_limits)
            except ValueError as error:
                logging.getLogger(__name__).warning("Ignoring invalid rate_limits: %s", error)

    def is_allowed(self, ip: str, endpoint: str, route: str | None) -> bool:
        with self._lock:
            # Match overrides by concrete path or route template. The default
            # stays per path so a page can fetch many different image URLs.
            bucket = endpoint if endpoint in self._limits else route
            limit = self._limits.get(bucket)
            if limit is None:
                bucket = endpoint if route is not None else "<unmatched>"
                limit = self._limits.get("default")
            if limit is None:
                return True
            max_requests, window = limit
            if max_requests == 0:
                return False
            now = time.monotonic()
            hits = self._requests.setdefault((ip, bucket), deque())
            cutoff = now - window
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= max_requests:
                return False
            hits.append(now)
            return True


