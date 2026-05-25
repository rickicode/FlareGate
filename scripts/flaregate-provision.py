#!/usr/bin/env python3
"""FlareGate Provisioner

Interactive helper to create or update a Cloudflare Tunnel + DNS record for a
single hostname on a NATed VPS.

Flow:
1) Ask for Cloudflare API token (or use CLOUDFLARE_API_TOKEN)
2) Ask for hostname (e.g. app.example.com)
3) Ask for upstream target (e.g. 127.0.0.1:3000, http://10.0.0.5:8080)
4) Reuse an existing tunnel for that hostname when a state file exists,
   otherwise create a fresh tunnel
5) Push tunnel ingress and DNS CNAME automatically

The script intentionally avoids external Python dependencies so it can run on
minimal VPS images.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib import error, parse, request

API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_CATCH_ALL = "http_status:404"
DEFAULT_STATE_DIR = Path.home() / ".local" / "share" / "flaregate"
USER_AGENT = "FlareGate-Provisioner/1.0"


class CloudflareError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


@dataclass
class ProvisionState:
    hostname: str
    target: str
    account_id: str
    zone_id: str
    zone_name: str
    tunnel_id: str
    tunnel_name: str
    dns_record_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "target": self.target,
            "account_id": self.account_id,
            "zone_id": self.zone_id,
            "zone_name": self.zone_name,
            "tunnel_id": self.tunnel_id,
            "tunnel_name": self.tunnel_name,
            "dns_record_id": self.dns_record_id,
            "updated_at": int(time.time()),
        }


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value)
    return value.strip(".-_") or "flaregate"


def state_path_for(hostname: str, state_dir: Optional[Path] = None) -> Path:
    state_dir = state_dir or DEFAULT_STATE_DIR
    return state_dir / f"{slugify(hostname)}.json"


def normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("target kosong")
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        return target
    return f"http://{target}"


def prompt(question: str, default: Optional[str] = None, secret: bool = False) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        if secret:
            value = getpass.getpass(f"{question}{suffix}: ")
        else:
            value = input(f"{question}{suffix}: ")
        value = value.strip()
        if value:
            return value
        if default is not None:
            return default
        print("Nilai tidak boleh kosong.")


def yes_no(question: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{question} [{hint}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "ya"}:
            return True
        if value in {"n", "no", "tidak"}:
            return False
        print("Jawab y atau n.")


def request_json(
    method: str,
    path: str,
    token: str,
    payload: Optional[Dict[str, Any]] = None,
    timeout: int = 20,
    retries: int = 4,
) -> Tuple[int, Dict[str, Any]]:
    url = f"{API_BASE}{path}"
    body = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        req = request.Request(url, data=body, headers=headers, method=method.upper())
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw) if raw else {}
                if isinstance(data, dict) and data.get("success") is False:
                    message = extract_cf_message(data) or f"Cloudflare API rejected request ({resp.status})"
                    raise CloudflareError(message, resp.status, data)
                return resp.status, data if isinstance(data, dict) else {"result": data}
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            data: Dict[str, Any] = {}
            if raw:
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        data = parsed
                except json.JSONDecodeError:
                    data = {}
            message = extract_cf_message(data) if data else raw.strip()
            message = message or f"HTTP {exc.code}"

            retryable = exc.code == 429 or exc.code >= 500
            if retryable and attempt < retries:
                time.sleep(backoff_seconds(attempt))
                last_error = CloudflareError(message, exc.code, data)
                continue
            raise CloudflareError(message, exc.code, data) from None
        except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt < retries:
                time.sleep(backoff_seconds(attempt))
                last_error = exc
                continue
            raise CloudflareError(f"Network/parse error: {exc}") from None

    raise CloudflareError(f"Request failed after retries: {last_error}")


def backoff_seconds(attempt: int) -> float:
    return min(2 ** attempt, 12) + (attempt * 0.15)


def extract_cf_message(data: Dict[str, Any]) -> str:
    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            msg = first.get("message")
            if msg:
                return str(msg)
    messages = data.get("messages")
    if isinstance(messages, list) and messages:
        first = messages[0]
        if isinstance(first, dict):
            msg = first.get("message")
            if msg:
                return str(msg)
    if isinstance(data.get("result"), dict):
        result = data["result"]
        if result.get("message"):
            return str(result["message"])
    if data.get("message"):
        return str(data["message"])
    return ""


def api_result(data: Dict[str, Any]) -> Any:
    return data.get("result")


def choose_from_results(label: str, items: Iterable[Dict[str, Any]], display_keys: Tuple[str, ...]) -> Dict[str, Any]:
    items = list(items)
    if not items:
        raise CloudflareError(f"Tidak ada {label} yang ditemukan")
    if len(items) == 1:
        return items[0]

    print(f"\nDitemukan beberapa {label}. Pilih salah satu:")
    for idx, item in enumerate(items, start=1):
        parts = []
        for key in display_keys:
            val = item.get(key)
            if val not in (None, ""):
                parts.append(f"{key}={val}")
        print(f"  {idx}. " + ", ".join(parts))

    while True:
        raw = input(f"Pilih {label} [1-{len(items)}]: ").strip()
        try:
            idx = int(raw)
        except ValueError:
            print("Masukkan angka.")
            continue
        if 1 <= idx <= len(items):
            return items[idx - 1]
        print("Di luar range.")


def resolve_account(token: str, account_id: Optional[str] = None) -> Dict[str, Any]:
    if account_id:
        _, data = request_json("GET", f"/accounts/{account_id}", token)
        result = api_result(data)
        if not isinstance(result, dict):
            raise CloudflareError("Response account tidak valid")
        return result

    _, data = request_json("GET", "/accounts?per_page=100", token)
    result = api_result(data)
    if not isinstance(result, list):
        raise CloudflareError("Response accounts tidak valid")
    chosen = choose_from_results("account", result, ("name", "id"))
    return chosen


def resolve_zone(token: str, hostname: str, zone_name: Optional[str] = None) -> Dict[str, Any]:
    if zone_name:
        _, data = request_json("GET", f"/zones?name={parse.quote(zone_name)}&status=active&per_page=100", token)
        result = api_result(data)
        if not isinstance(result, list) or not result:
            raise CloudflareError(f"Zone '{zone_name}' tidak ditemukan")
        chosen = choose_from_results("zone", result, ("name", "id"))
        return chosen

    labels = hostname.split(".")
    while len(labels) >= 2:
        candidate = ".".join(labels)
        _, data = request_json("GET", f"/zones?name={parse.quote(candidate)}&status=active&per_page=100", token)
        result = api_result(data)
        if isinstance(result, list) and result:
            exact = [z for z in result if isinstance(z, dict) and z.get("name") == candidate]
            if exact:
                return exact[0]
            return choose_from_results("zone", result, ("name", "id"))
        labels = labels[1:]

    raise CloudflareError(
        "Tidak bisa menemukan zone Cloudflare dari hostname. "
        "Coba jalankan lagi dan isi --zone-name secara manual."
    )


def list_dns_records(token: str, zone_id: str, hostname: str) -> list[Dict[str, Any]]:
    _, data = request_json("GET", f"/zones/{zone_id}/dns_records?name={parse.quote(hostname)}&per_page=100", token)
    result = api_result(data)
    if not isinstance(result, list):
        return []
    records: list[Dict[str, Any]] = []
    for rec in result:
        if isinstance(rec, dict) and rec.get("name") == hostname:
            records.append(rec)
    return records


def delete_dns_record(token: str, zone_id: str, record_id: str) -> None:
    if not record_id:
        return
    request_json("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token)


def ensure_dns_record(token: str, zone_id: str, zone_name: str, hostname: str, tunnel_id: str) -> Dict[str, Any]:
    content = f"{tunnel_id}.cfargotunnel.com"
    payload = {
        "type": "CNAME",
        "name": hostname,
        "content": content,
        "proxied": True,
        "comment": "Managed by FlareGate",
    }

    records = list_dns_records(token, zone_id, hostname)
    desired_cname: Optional[Dict[str, Any]] = None
    conflicting_records: list[Dict[str, Any]] = []

    for record in records:
        rtype = str(record.get("type", "")).upper()
        if rtype == "CNAME":
            desired_cname = record
        else:
            conflicting_records.append(record)

    for record in conflicting_records:
        record_id = str(record.get("id", "")).strip()
        if record_id:
            print(f"[DNS] Removing conflicting {record.get('type')} record for {hostname}: {record_id}")
            delete_dns_record(token, zone_id, record_id)

    if desired_cname:
        record_id = str(desired_cname.get("id", "")).strip()
        if desired_cname.get("content") == content and bool(desired_cname.get("proxied", True)) is True:
            return desired_cname
        _, data = request_json("PUT", f"/zones/{zone_id}/dns_records/{record_id}", token, payload)
        result = api_result(data)
        if not isinstance(result, dict):
            raise CloudflareError("Gagal update DNS record")
        return result

    _, data = request_json("POST", f"/zones/{zone_id}/dns_records", token, payload)
    result = api_result(data)
    if not isinstance(result, dict):
        raise CloudflareError("Gagal create DNS record")
    return result


def normalize_service(service: str) -> str:
    service = service.strip()
    if not service:
        raise ValueError("service kosong")
    return normalize_target(service)


def get_state_path(args: argparse.Namespace, hostname: str) -> Path:
    if args.state_file:
        return Path(args.state_file).expanduser()
    return state_path_for(hostname, Path(args.state_dir).expanduser())


def load_state(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_state(path: Path, state: ProvisionState, extra: Optional[Dict[str, Any]] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = state.to_dict()
    if extra:
        payload.update(extra)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def create_or_update_tunnel(
    token: str,
    account_id: str,
    hostname: str,
    target: str,
    tunnel_name: str,
    existing_state: Optional[Dict[str, Any]],
    force_new_tunnel: bool,
    zone_name: Optional[str] = None,
) -> Tuple[ProvisionState, Dict[str, Any], Dict[str, Any]]:
    """Return (state, tunnel_result, dns_result)."""
    if existing_state and not force_new_tunnel:
        tunnel_id = str(existing_state.get("tunnel_id", "")).strip()
        zone_id = str(existing_state.get("zone_id", "")).strip()
        zn = str(existing_state.get("zone_name", "")).strip()
        if tunnel_id and zone_id and zn:
            tunnel_result = {"id": tunnel_id, "name": existing_state.get("tunnel_name", tunnel_name)}
            state = ProvisionState(
                hostname=hostname, target=target, account_id=account_id,
                zone_id=zone_id, zone_name=zn, tunnel_id=tunnel_id,
                tunnel_name=str(existing_state.get("tunnel_name", tunnel_name)),
                dns_record_id=str(existing_state.get("dns_record_id", "")),
            )
            return state, tunnel_result, {}

    payload = {"name": tunnel_name, "config_src": "cloudflare"}
    _, data = request_json("POST", f"/accounts/{account_id}/cfd_tunnel", token, payload)
    result = api_result(data)
    if not isinstance(result, dict):
        raise CloudflareError("Create tunnel response tidak valid")

    tunnel_id = str(result.get("id", "")).strip()
    if not tunnel_id:
        raise CloudflareError("Tunnel ID tidak ditemukan pada response create tunnel")

    # Zone resolution — use explicit zone_name first, fall back to auto-detection.
    zn = zone_name
    zone_result: Dict[str, Any] = {}
    zone_id = ""
    if zn:
        zone_result = resolve_zone(token, hostname, zone_name=zn)
        zone_id = str(zone_result.get("id", "")).strip()
        zn = str(zone_result.get("name", "")).strip()
    if not zone_id:
        zone_result = resolve_zone(token, hostname)
        zone_id = str(zone_result.get("id", "")).strip()
        zn = str(zone_result.get("name", "")).strip()
    if not zone_id or not zn:
        raise CloudflareError("Zone data tidak lengkap")

    state = ProvisionState(
        hostname=hostname, target=target, account_id=account_id,
        zone_id=zone_id, zone_name=zn, tunnel_id=tunnel_id, tunnel_name=tunnel_name,
    )
    return state, result, zone_result


def update_ingress(token: str, account_id: str, tunnel_id: str, hostname: str, target: str) -> Dict[str, Any]:
    payload = {
        "config": {
            "ingress": [
                {
                    "hostname": hostname,
                    "service": target,
                    "originRequest": {},
                },
                {
                    "service": DEFAULT_CATCH_ALL,
                },
            ]
        }
    }
    _, data = request_json(
        "PUT",
        f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations",
        token,
        payload,
    )
    result = api_result(data)
    if not isinstance(result, dict):
        raise CloudflareError("Gagal update ingress tunnel")
    return result


def fetch_tunnel_token(token: str, account_id: str, tunnel_id: str) -> str:
    _, data = request_json("GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token", token)
    result = api_result(data)
    if isinstance(result, str) and result:
        return result
    if isinstance(result, dict) and result.get("token"):
        return str(result["token"])
    raise CloudflareError("Tunnel token tidak ditemukan pada response")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interactive Cloudflare Tunnel + DNS provisioner for NAT VPS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--token", help="Cloudflare API token (or env CLOUDFLARE_API_TOKEN)")
    parser.add_argument("--hostname", help="Public hostname to create, e.g. app.example.com")
    parser.add_argument("--target", help="Upstream target, e.g. 127.0.0.1:3000 or http://10.0.0.5:8080")
    parser.add_argument("--tunnel-name", help="Tunnel name (defaults to hostname-based slug)")
    parser.add_argument("--account-id", help="Cloudflare account ID (skip account selection)")
    parser.add_argument("--zone-name", help="Cloudflare zone name if auto-detection fails")
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR), help="Directory for saved state files")
    parser.add_argument("--state-file", help="Explicit state file path (overrides --state-dir)")
    parser.add_argument("--force-new-tunnel", action="store_true", help="Always create a fresh tunnel")
    parser.add_argument("--print-json", action="store_true", help="Print machine-readable result JSON")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    token = args.token or os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        token = prompt("Cloudflare API token", secret=True)

    hostname = args.hostname or prompt("Domain/subdomain yang mau dipakai", default="app.example.com")
    hostname = hostname.strip().lower().rstrip(".")
    if not hostname or "." not in hostname:
        eprint("Hostname harus berupa FQDN, contoh: app.example.com")
        return 2

    raw_target = args.target or prompt("Mau di-forward ke mana? (ip:port atau URL)", default="127.0.0.1:3000")
    try:
        target = normalize_service(raw_target)
    except ValueError as exc:
        eprint(str(exc))
        return 2

    tunnel_name = args.tunnel_name or f"flaregate-{slugify(hostname)}"
    state_path = get_state_path(args, hostname)
    existing_state = load_state(state_path)
    if existing_state and not args.force_new_tunnel:
        print(f"[Info] State ditemukan, akan pakai tunnel existing: {state_path}")
        tunnel_name = str(existing_state.get("tunnel_name", tunnel_name))

    try:
        preferred_account_id = None
        if existing_state and not args.account_id:
            preferred_account_id = str(existing_state.get("account_id", "")).strip() or None

        account = resolve_account(token, args.account_id or preferred_account_id)
        account_id = str(account.get("id", "")).strip()
        if not account_id:
            raise CloudflareError("Account ID tidak ditemukan")

        state, tunnel_result, zone_result = create_or_update_tunnel(
            token=token,
            account_id=account_id,
            hostname=hostname,
            target=target,
            tunnel_name=tunnel_name,
            existing_state=existing_state,
            force_new_tunnel=args.force_new_tunnel,
            zone_name=args.zone_name,
        )

        # If we created a fresh tunnel, zone_result is the resolved zone object.
        # If we reused the tunnel, resolve zone now so DNS can be reconciled.
        if not state.zone_id or not state.zone_name:
            zone_result = resolve_zone(token, hostname, args.zone_name)
            state.zone_id = str(zone_result.get("id", "")).strip()
            state.zone_name = str(zone_result.get("name", "")).strip()

        ingress_result = update_ingress(token, state.account_id, state.tunnel_id, state.hostname, state.target)
        dns_result = ensure_dns_record(token, state.zone_id, state.zone_name, state.hostname, state.tunnel_id)
        state.dns_record_id = str(dns_result.get("id", existing_state.get("dns_record_id", "") if existing_state else ""))
        save_state(state_path, state)

        tunnel_token = fetch_tunnel_token(token, state.account_id, state.tunnel_id)

        print("\n✅ Selesai!")
        print(f"- Hostname      : {state.hostname}")
        print(f"- Target        : {state.target}")
        print(f"- Zone          : {state.zone_name} ({state.zone_id})")
        print(f"- Tunnel name   : {state.tunnel_name}")
        print(f"- Tunnel ID     : {state.tunnel_id}")
        print(f"- DNS record ID : {state.dns_record_id or '-'}")
        print(f"- State file    : {state_path}")
        print("\nJalankan cloudflared di VPS:")
        print(f"  sudo cloudflared service install {tunnel_token}")
        print("\nAtau untuk tes manual:")
        print(f"  cloudflared tunnel run --token {tunnel_token}")
        print("\nCatatan:")
        print("- DNS CNAME sudah diarahkan ke <tunnel-id>.cfargotunnel.com")
        print("- Ingress sudah dipasang ke hostname -> target")
        print(f"- Catch-all fallback: {DEFAULT_CATCH_ALL}")
        print("- Token tunnel hanya ditampilkan sekali di sini, simpan kalau perlu")

        if args.print_json:
            output = {
                "success": True,
                "hostname": state.hostname,
                "target": state.target,
                "account_id": state.account_id,
                "zone_id": state.zone_id,
                "zone_name": state.zone_name,
                "tunnel_id": state.tunnel_id,
                "tunnel_name": state.tunnel_name,
                "dns_record_id": state.dns_record_id,
                "state_file": str(state_path),
                "ingress_result": ingress_result,
                "dns_result": dns_result,
            }
            print(json.dumps(output, indent=2, sort_keys=True))
        return 0

    except CloudflareError as exc:
        eprint(f"[Error] {exc}")
        if exc.status:
            eprint(f"[Error] HTTP status: {exc.status}")
        if exc.payload:
            try:
                eprint("[Debug] Payload:")
                eprint(json.dumps(exc.payload, indent=2, sort_keys=True))
            except Exception:
                pass
        return 1
    except KeyboardInterrupt:
        eprint("\nDibatalkan.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
