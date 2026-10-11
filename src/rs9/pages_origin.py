"""Read-only fixed public Pages origin diagnostics for rs9.knowledge-forge.ai.

Validates exact original relative paths with standard certificate and hostname
verification. Uses http.client.HTTPConnection over an already-verified TLS socket
with per-stage timeouts, bounded headers/body, and stage diagnostics.
Failure at any stage stays state=unknown; exact authenticated 404 yields absent;
unchanged content comparison yields exact.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import socket
import ssl
import argparse
import json
import math
import subprocess
import sys
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from rs9.errors import ContractError
from rs9.readers import classify_tls_error, extract_tls_verify_code
from rs9.records import validate_sha256
from rs9.security import scan_for_credentials, validate_safe_relative_posix_path

SCHEMA = "rs9.pages-origin-diagnostic.v1alpha1"
PAGES_ORIGIN_HOST = "rs9.knowledge-forge.ai"
PAGES_ORIGIN_PORT = 443
MAX_RESPONSE_BODY = 16 * 1024 * 1024
DEFAULT_TIMEOUTS = {
    "dns": 5.0,
    "tcp": 5.0,
    "tls": 5.0,
    "http": 5.0,
}


def _make_diagnostic(
    path: str,
    *,
    state: str,
    stage: str,
    class_token: str,
    code: int | None = None,
    diagnostics: list[dict[str, str]] | None = None,
    dns_safe: dict[str, Any] | None = None,
    origin_verified: bool = False,
    body_sha256: str | None = None,
) -> dict[str, Any]:
    bounded_code: int | None = None
    if isinstance(code, int) and -1000 <= code <= 1000:
        bounded_code = code

    doc: dict[str, Any] = {
        "schema": SCHEMA,
        "target": PAGES_ORIGIN_HOST,
        "port": PAGES_ORIGIN_PORT,
        "path": path,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "state": state,
        "stage": stage,
        "class": class_token,
        "code": bounded_code,
        "dns_safe": dns_safe or {"host": PAGES_ORIGIN_HOST},
        "origin_verified": bool(origin_verified),
        "diagnostics": diagnostics or [],
    }
    if body_sha256 is not None:
        doc["body_sha256"] = body_sha256
    return doc


def validate_origin_path(path: str) -> str:
    """Validate safe relative posix path and verify absence of credentials."""
    clean = path
    if not clean:
        raise ContractError("PATH_EMPTY", "Pages origin relative path required")
    validate_safe_relative_posix_path(clean)
    if len(clean) > 512 or any(c in clean for c in "?#%:@ "):
        raise ContractError("UNSAFE_PATH", "Exact public relative object path required")
    scan_for_credentials(clean)
    return clean


def _resolve_origin(timeout):
    """Bound getaddrinfo with a child that is killed and reaped on timeout."""
    code = '''import json,socket
try:
    rows=socket.getaddrinfo("rs9.knowledge-forge.ai",443,socket.AF_UNSPEC,socket.SOCK_STREAM)
    print(json.dumps({"addresses":rows[:64]}))
except socket.gaierror as error:
    print(json.dumps({"dns_error":error.errno}))
'''
    result = subprocess.run([sys.executable, "-c", code], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise OSError("dns-unavailable")
    record = json.loads(result.stdout)
    if "dns_error" in record:
        raise socket.gaierror(record["dns_error"], "dns-unavailable")
    return record["addresses"]


def _bounded_body(response, tls_sock, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) <= MAX_RESPONSE_BODY:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        if tls_sock is not None:
            tls_sock.settimeout(remaining)
        reader = getattr(response, "read1", response.read)
        part = reader(min(65536, MAX_RESPONSE_BODY + 1 - len(data)))
        if not part:
            break
        data.extend(part)
    return data


def diagnose_pages_origin(
    path: str = "CNAME",
    *,
    expected_sha256: str | None = None,
    timeouts: Mapping[str, float] | None = None,
    _addr_info: list[Any] | None = None,
    _sock: Any | None = None,
    _tls_sock: Any | None = None,
    _conn: Any | None = None,
) -> dict[str, Any]:
    """Perform read-only origin diagnostic probe against fixed target rs9.knowledge-forge.ai.

    Executes DNS, TCP, TLS, and HTTP stages sequentially with per-stage timeouts
    and standard certificate AND hostname verification. Failure at any stage
    stays unknown; exact authenticated 404 yields absent; content match yields exact.
    Carries strictly no observation or hosted authority.
    """
    clean_path = validate_origin_path(path)
    if expected_sha256:
        validate_sha256(expected_sha256)

    t_map = dict(DEFAULT_TIMEOUTS)
    if timeouts:
        if set(timeouts) - set(t_map):
            raise ContractError("PAGES_TIMEOUT", "Unknown diagnostic timeout stage")
        t_map.update(timeouts)
    if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 < v <= 30
           for v in t_map.values()):
        raise ContractError("PAGES_TIMEOUT", "Bounded positive stage timeouts required")

    dns_safe: dict[str, Any] = {"host": PAGES_ORIGIN_HOST}

    # 1. DNS stage
    addr_info = [] if _conn is not None or _tls_sock is not None else _addr_info
    if addr_info is None:
        try:
            addr_info = _resolve_origin(t_map["dns"])
            if not addr_info:
                return _make_diagnostic(
                    clean_path,
                    state="unknown",
                    stage="dns",
                    class_token="dns-unknown",
                    code=None,
                    diagnostics=[{"code": "pages-origin-dns-empty", "message": "DNS returned no addresses"}],
                    dns_safe=dns_safe,
                )
            families = sorted(list({
                "ipv4" if r[0] == socket.AF_INET else "ipv6" if r[0] == socket.AF_INET6 else "unknown"
                for r in addr_info
            }))
            dns_safe["families"] = families
            dns_safe["count"] = len(addr_info)
            public_addrs: list[str] = []
            for r in addr_info:
                ip_str = r[4][0]
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_global and not ip_obj.is_private and not ip_obj.is_loopback:
                        if ip_str not in public_addrs:
                            public_addrs.append(ip_str)
                except ValueError:
                    pass
            if public_addrs:
                dns_safe["addresses"] = public_addrs[:4]
        except (socket.gaierror, socket.herror) as exc:
            errno_val = exc.errno if isinstance(exc.errno, int) and -1000 <= exc.errno <= 1000 else None
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="dns",
                class_token="dns-unknown",
                code=errno_val,
                diagnostics=[{"code": "pages-origin-dns-unknown", "message": "DNS resolution unavailable"}],
                dns_safe=dns_safe,
            )
        except (TimeoutError, subprocess.TimeoutExpired):
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="dns",
                class_token="timeout",
                code=None,
                diagnostics=[{"code": "pages-origin-dns-timeout", "message": "DNS resolution timed out"}],
                dns_safe=dns_safe,
            )
        except (OSError, ValueError, KeyError, TypeError):
            return _make_diagnostic(clean_path, state="unknown", stage="dns",
                                    class_token="dns-unknown", dns_safe=dns_safe)

    # 2. TCP stage
    raw_sock = _sock
    created_raw = False
    if raw_sock is None and _tls_sock is None and _conn is None:
        family, socktype, proto, canonname, sockaddr = addr_info[0]
        try:
            raw_sock = socket.socket(family, socktype, proto)
            created_raw = True
            raw_sock.settimeout(t_map.get("tcp", 5.0))
            raw_sock.connect(tuple(sockaddr))
        except (TimeoutError, socket.timeout):
            raw_sock.close()
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tcp",
                class_token="timeout",
                code=None,
                diagnostics=[{"code": "pages-origin-tcp-timeout", "message": "TCP connection timed out"}],
                dns_safe=dns_safe,
            )
        except ConnectionRefusedError as exc:
            raw_sock.close()
            errno_val = exc.errno if isinstance(exc.errno, int) and -1000 <= exc.errno <= 1000 else None
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tcp",
                class_token="connection-refused",
                code=errno_val,
                diagnostics=[{"code": "pages-origin-tcp-connection-refused", "message": "TCP connection refused"}],
                dns_safe=dns_safe,
            )
        except OSError as exc:
            if raw_sock is not None:
                raw_sock.close()
            errno_val = exc.errno if isinstance(exc.errno, int) and -1000 <= exc.errno <= 1000 else None
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tcp",
                class_token="transport-error",
                code=errno_val,
                diagnostics=[{"code": "pages-origin-tcp-transport-error", "message": "TCP connection failed"}],
                dns_safe=dns_safe,
            )

    # 3. TLS stage
    tls_sock = _tls_sock
    created_tls = False
    if tls_sock is None and _conn is None:
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = True
            ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            raw_sock.settimeout(t_map.get("tls", 5.0))
            tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=PAGES_ORIGIN_HOST)
            created_tls = True
            tls_sock.settimeout(t_map.get("tls", 5.0))
        except (ssl.SSLError, getattr(ssl, "CertificateError", ())) as exc:
            if created_raw and raw_sock is not None:
                raw_sock.close()
            token = classify_tls_error(exc)
            verify_code = extract_tls_verify_code(exc)
            diags = [
                {"code": "pages-origin-tls-error", "message": f"TLS failure: {token}"},
                {"code": f"pages-origin-tls-{token}", "message": f"TLS failure class {token}"},
            ]
            if verify_code is not None:
                diags.append({"code": "pages-origin-tls-verify-code", "message": f"TLS verify code {verify_code}"})
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tls",
                class_token=token,
                code=verify_code,
                diagnostics=diags,
                dns_safe=dns_safe,
            )
        except (TimeoutError, socket.timeout):
            if created_raw and raw_sock is not None:
                raw_sock.close()
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tls",
                class_token="timeout",
                code=None,
                diagnostics=[{"code": "pages-origin-tls-timeout", "message": "TLS handshake timed out"}],
                dns_safe=dns_safe,
            )
        except OSError as exc:
            if created_raw and raw_sock is not None:
                raw_sock.close()
            errno_val = exc.errno if isinstance(exc.errno, int) and -1000 <= exc.errno <= 1000 else None
            return _make_diagnostic(
                clean_path,
                state="unknown",
                stage="tls",
                class_token="transport-error",
                code=errno_val,
                diagnostics=[{"code": "pages-origin-tls-transport-error", "message": "TLS transport error"}],
                dns_safe=dns_safe,
            )

    # 4. HTTP stage over already-verified TLS socket
    conn = _conn
    created_conn = False
    response = None
    try:
        if tls_sock is not None:
            tls_sock.settimeout(t_map["http"])
        if conn is None:
            conn = http.client.HTTPConnection(
                PAGES_ORIGIN_HOST,
                port=PAGES_ORIGIN_PORT,
                timeout=t_map.get("http", 5.0),
            )
            created_conn = True
            conn.sock = tls_sock

        headers = {
            "User-Agent": "RS9-readback-v1alpha1",
            "Host": PAGES_ORIGIN_HOST,
            "Accept": "*/*",
            "Connection": "close",
        }
        conn.request("GET", "/" + clean_path, headers=headers)
        response = conn.getresponse()
        status = response.status

        # Redirects: rejected, failure stays unknown, no cross-host redirect
        if status in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            redirect = urlsplit(location)
            doc = _make_diagnostic(
                clean_path,
                state="unknown",
                stage="redirect",
                class_token="redirect-rejected",
                code=status,
                diagnostics=[{"code": "pages-origin-redirect-rejected", "message": f"Redirect {status} rejected"}],
                dns_safe=dns_safe,
                origin_verified=True,
            )
            doc["redirect_same_host"] = bool(location and (not redirect.netloc or
                (redirect.hostname == PAGES_ORIGIN_HOST and redirect.scheme in ("", "https"))))
            return doc

        # Exact authenticated 404: origin evidence verified, yields absent
        if status == 404:
            return _make_diagnostic(
                clean_path,
                state="absent",
                stage="http",
                class_token="authenticated-404",
                code=404,
                diagnostics=[{"code": "pages-origin-exact-404", "message": "Exact authenticated 404 on origin"}],
                dns_safe=dns_safe,
                origin_verified=True,
            )

        # 200 OK: comparison stage
        if status == 200:
            data = _bounded_body(response, tls_sock, t_map["http"])
            if len(data) > MAX_RESPONSE_BODY:
                return _make_diagnostic(
                    clean_path,
                    state="unknown",
                    stage="http",
                    class_token="response-limit-exceeded",
                    code=200,
                    diagnostics=[{"code": "pages-origin-response-limit", "message": "Response body exceeded limit"}],
                    dns_safe=dns_safe,
                    origin_verified=True,
                )
            data_sha = hashlib.sha256(data).hexdigest()
            if expected_sha256 is not None:
                if data_sha == expected_sha256:
                    return _make_diagnostic(
                        clean_path,
                        state="exact",
                        stage="comparison",
                        class_token="comparison-match",
                        code=200,
                        diagnostics=[{"code": "pages-origin-comparison-match", "message": "Content SHA256 matched expected"}],
                        dns_safe=dns_safe,
                        origin_verified=True,
                        body_sha256=data_sha,
                    )
                return _make_diagnostic(
                    clean_path,
                    state="unknown",
                    stage="comparison",
                    class_token="comparison-mismatch",
                    code=200,
                    diagnostics=[{"code": "pages-origin-hash-conflict", "message": "Content SHA256 differs from expected"}],
                    dns_safe=dns_safe,
                    origin_verified=True,
                    body_sha256=data_sha,
                )
            return _make_diagnostic(
                clean_path,
                state="present",
                stage="http",
                class_token="http-ok",
                code=200,
                diagnostics=[{"code": "pages-origin-present", "message": "Origin object present"}],
                dns_safe=dns_safe,
                origin_verified=True,
                body_sha256=data_sha,
            )

        # Any other HTTP status (403, 500, 502, 503, etc.) stays unknown
        return _make_diagnostic(
            clean_path,
            state="unknown",
            stage="http",
            class_token="http-error",
            code=status,
            diagnostics=[{"code": "pages-origin-http-error", "message": f"HTTP status {status}"}],
            dns_safe=dns_safe,
            origin_verified=True,
        )
    except (TimeoutError, socket.timeout):
        return _make_diagnostic(
            clean_path,
            state="unknown",
            stage="http",
            class_token="timeout",
            code=None,
            diagnostics=[{"code": "pages-origin-http-timeout", "message": "HTTP response timed out"}],
            dns_safe=dns_safe,
            origin_verified=True,
        )
    except (http.client.HTTPException, OSError, ValueError) as exc:
        errno_val = getattr(exc, "errno", None)
        if not (isinstance(errno_val, int) and -1000 <= errno_val <= 1000):
            errno_val = None
        return _make_diagnostic(
            clean_path,
            state="unknown",
            stage="http",
            class_token="protocol-error",
            code=errno_val,
            diagnostics=[{"code": "pages-origin-protocol-error", "message": "HTTP protocol failure"}],
            dns_safe=dns_safe,
            origin_verified=True,
        )
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if created_conn and conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        elif created_tls and tls_sock is not None:
            try:
                tls_sock.close()
            except Exception:
                pass
        elif created_raw and raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default="CNAME")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)
    print(json.dumps(diagnose_pages_origin(args.path, expected_sha256=args.expected_sha256),
                     sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
