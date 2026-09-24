"""Host-side client for the REMnux static-analysis worker (malloop/worker/worker_agent.py).

Uploads a file to the worker over the host-only network and returns each tool's raw JSON. Parsing
stays on the host (static_analysis._parse_capa / _parse_floss), so it is testable without a worker.
"""
import requests

from . import config


class StaticWorker:
    def __init__(self, url: str, token: str, timeout: int):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _headers(self, **extra) -> dict:
        return {"X-Malloop-Token": self.token, **extra}

    def health(self) -> dict:
        r = requests.get(f"{self.url}/health", headers=self._headers(), timeout=10)
        r.raise_for_status()
        return r.json()

    def analyze(self, path, tools=("capa", "floss")) -> dict:
        """Return {tool: {"ok", "result"} | {"skipped"|"error"}}. Never raises; failures come back as errors."""
        try:
            with open(path, "rb") as f:
                r = requests.post(
                    f"{self.url}/analyze",
                    headers=self._headers(**{"X-Malloop-Tools": ",".join(tools)}),
                    files={"file": (getattr(path, "name", "sample"), f)},
                    timeout=self.timeout,
                )
            r.raise_for_status()
            return r.json()
        except requests.RequestException as e:
            reason = f"static worker unreachable at {self.url}: {e}"
            return {t: {"error": reason} for t in tools}


def get_static_worker() -> "StaticWorker | None":
    if not config.STATIC_WORKER_URL:
        return None
    return StaticWorker(config.STATIC_WORKER_URL, config.STATIC_WORKER_TOKEN, config.STATIC_WORKER_TIMEOUT)
