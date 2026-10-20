"""Minimal OPNsense REST API client (stdlib only)."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .config import OPNsenseCfg


class OPNsenseError(RuntimeError):
    pass


class OPNsense:
    def __init__(self, cfg: OPNsenseCfg):
        if not cfg.url:
            raise OPNsenseError("opnsense.url is not configured")
        self.base = cfg.url.rstrip("/")
        self.cfg = cfg
        token = base64.b64encode(f"{cfg.api_key}:{cfg.api_secret}".encode()).decode()
        self._auth = f"Basic {token}"
        if not cfg.verify_tls:
            self._ctx = ssl._create_unverified_context()  # noqa: S323 - user opted out
        elif cfg.ca_file:
            self._ctx = ssl.create_default_context(cafile=cfg.ca_file)
        else:
            self._ctx = ssl.create_default_context()

    def _req(self, method: str, path: str, body: dict | None = None, query: dict | None = None):
        url = f"{self.base}/api/{path.lstrip('/')}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self._auth)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as e:
            raise OPNsenseError(f"{method} {path}: HTTP {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise OPNsenseError(f"{method} {path}: {e.reason}") from e
        try:
            return json.loads(payload or b"{}")
        except json.JSONDecodeError as e:
            raise OPNsenseError(f"{method} {path}: non-JSON response") from e

    # --- IDS -------------------------------------------------------------
    def ids_alerts(self, page: int = 1, rows: int = 500, search: str = "") -> list[dict]:
        """Newest-first page of Suricata alerts from the current eve log."""
        res = self._req("POST", "ids/service/query_alerts",
                        body={"current": page, "rowCount": rows, "searchPhrase": search, "fileid": ""})
        return res.get("rows", [])

    def ids_status(self) -> dict:
        return self._req("GET", "ids/service/status")

    # --- Firewall log ----------------------------------------------------
    def firewall_log(self, limit: int = 2000) -> list[dict]:
        res = self._req("GET", "diagnostics/firewall/log", query={"limit": limit})
        return res if isinstance(res, list) else res.get("rows", [])

    # --- Alias management (auto-block) -----------------------------------
    def alias_add(self, alias: str, address: str) -> dict:
        return self._req("POST", f"firewall/alias_util/add/{urllib.parse.quote(alias)}",
                         body={"address": address})

    def alias_delete(self, alias: str, address: str) -> dict:
        return self._req("POST", f"firewall/alias_util/delete/{urllib.parse.quote(alias)}",
                         body={"address": address})

    def alias_list(self, alias: str) -> list[str]:
        res = self._req("GET", f"firewall/alias_util/list/{urllib.parse.quote(alias)}")
        return [r.get("ip") for r in res.get("rows", [])]
