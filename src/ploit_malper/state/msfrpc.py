"""MSF-RPC client for Metasploit workspace verification and host notes."""

import requests
import msgpack
from typing import Optional
from dataclasses import dataclass
from rich.console import Console

console = Console()


@dataclass
class MSFHostInfo:
    address: str
    os_name: Optional[str]
    os_flavor: Optional[str]
    state: str
    notes_count: int


@dataclass
class MSFWorkspace:
    name: str
    scope: str
    host_count: int


class MSFRPCClient:
    def __init__(self, host: str, port: int, username: str, password: str, ssl: bool = True) -> None:
        self.host = host
        self.port = port
        self.ssl = ssl
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self._base_url = f"{'https' if ssl else 'http'}://{host}:{port}"

    def login(self) -> bool:
        try:
            payload = msgpack.packb({
                "method": "auth.login",
                "params": [self.username, self.password],
            })
            resp = requests.post(
                f"{self._base_url}/api/1.1",
                data=payload,
                headers={"Content-Type": "binary/message-pack"},
                verify=False,
                timeout=10,
            )
            result = msgpack.unpackb(resp.content, raw=False)
            if result.get("result") == "success":
                self.token = result.get("token")
                return True
            return False
        except (requests.RequestException, Exception) as e:
            console.print(f"[!] MSF-RPC connection failed: {e}")
            return False

    def logout(self) -> None:
        if self.token:
            try:
                payload = msgpack.packb({
                    "method": "auth.logout",
                    "params": [self.token],
                })
                requests.post(
                    f"{self._base_url}/api/1.1",
                    data=payload,
                    headers={"Content-Type": "binary/message-pack"},
                    verify=False,
                    timeout=5,
                )
            except Exception:
                pass
            finally:
                self.token = None

    def _call(self, method: str, params: list) -> dict:
        if not self.token:
            raise RuntimeError("Not authenticated to MSF-RPC")
        payload = msgpack.packb({
            "method": method,
            "params": [self.token] + params,
        })
        resp = requests.post(
            f"{self._base_url}/api/1.1",
            data=payload,
            headers={"Content-Type": "binary/message-pack"},
            verify=False,
            timeout=15,
        )
        return msgpack.unpackb(resp.content, raw=False)

    def get_workspaces(self) -> list[MSFWorkspace]:
        try:
            result = self._call("db.workspaces", [])
            workspaces = []
            if isinstance(result, dict):
                for ws in result.get("workspaces", []):
                    workspaces.append(MSFWorkspace(
                        name=ws.get("name", "unknown"),
                        scope=ws.get("scope", ""),
                        host_count=ws.get("hosts_count", 0),
                    ))
            return workspaces
        except Exception as e:
            console.print(f"[!] Failed to fetch workspaces: {e}")
            return []

    def get_hosts(self, workspace: Optional[str] = None) -> list[MSFHostInfo]:
        try:
            params = []
            if workspace:
                params.append({"workspace": workspace})
            result = self._call("db.hosts", params)
            hosts = []
            if isinstance(result, dict):
                for h in result.get("hosts", []):
                    hosts.append(MSFHostInfo(
                        address=h.get("address", "unknown"),
                        os_name=h.get("os_name"),
                        os_flavor=h.get("os_flavor"),
                        state=h.get("state", "unknown"),
                        notes_count=h.get("notes_count", 0),
                    ))
            return hosts
        except Exception as e:
            console.print(f"[!] Failed to fetch hosts: {e}")
            return []

    def get_notes(self, host: str) -> list[dict]:
        try:
            result = self._call("db.notes", [{"host": host}])
            if isinstance(result, dict):
                return result.get("notes", [])
            return []
        except Exception as e:
            console.print(f"[!] Failed to fetch notes for {host}: {e}")
            return []

    def check_host_exists(self, address: str, workspace: Optional[str] = None) -> bool:
        hosts = self.get_hosts(workspace)
        return any(h.address == address for h in hosts)
