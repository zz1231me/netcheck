#!/usr/bin/env python3
# netcheck — 계층별 도달성 진단
#
# 접속 실패 지점을 계층(L0~L9)과 구간 단위로 찾는다.
# 계층마다 독립된 방법으로 검사하고 정상 대조군과 비교해 원인 구간과 조치를 출력한다.
#
#   ./tools/netcheck.py apis.data.go.kr
#   ./tools/netcheck.py -f apis.data.go.kr:443 www.weather.go.kr:443
#   ./tools/netcheck.py --proxy http://proxy.corp:3128 apis.data.go.kr
#   ./tools/netcheck.py --json apis.data.go.kr > report.json
#
# 표준 라이브러리만 사용. 외부 명령은 원시 소켓이 필요한 경우만 호출:
#   macOS/Linux: traceroute, ping     Windows: tracert, ping, route, netsh
# Python 3.8+ · macOS / Linux / Windows

from __future__ import annotations

import argparse
import base64
import concurrent.futures as futures
import contextlib
import errno as E
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urljoin, urlsplit

VERSION = "3.0"
IS_MAC = platform.system() == "Darwin"
IS_WIN = platform.system() == "Windows"

# Windows 명령 출력은 표시 언어에 따라 번역되므로 번역되지 않는 값만 읽는다:
# 레지스트리(DNS·프록시), route print 숫자 열, ping/tracert 의 숫자·'ms'·'TTL=' 토큰.


def enable_ansi() -> bool:
    """Windows 콘솔의 VT 처리를 켠다. 실패하면 False (색 없이 출력)."""
    if not IS_WIN:
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))   # VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        return False


# 중단 확인 콜백. run_diagnosis 가 실행 중에만 설정한다 (예외를 던져 중단).
ABORT: Optional[Callable[[], None]] = None


def run_cmd(cmd: list[str], timeout: float = 6.0) -> str:
    """외부 명령 실행. 디코딩 오류는 대체 문자로 처리한다.

    실행 중 ABORT 를 주기적으로 확인하고, 중단 요청이 오면 프로세스를 종료한 뒤 예외를 전파한다."""
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL,
                             creationflags=(0x08000000 if IS_WIN else 0))   # 창 안 띄우기
    except (OSError, ValueError):
        return ""
    end = time.monotonic() + timeout
    try:
        while True:
            try:
                out, _ = p.communicate(timeout=min(0.25, max(0.01, end - time.monotonic())))
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= end:
                    # 시간 초과: 종료하고 그때까지의 출력을 돌려준다 (traceroute 부분 결과 보존)
                    p.kill()
                    out, _ = p.communicate()
                    break
                if ABORT:
                    ABORT()
    except BaseException:
        p.kill()
        p.communicate()
        raise
    return (out or b"").decode("utf-8", "replace")


def local_ip_for(dst: str = "1.1.1.1") -> str:
    """목적지로 나갈 때 쓰는 로컬 주소. UDP connect 로 경로만 조회하며 패킷은 보내지 않는다."""
    fam = socket.AF_INET6 if ":" in dst else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.connect((dst, 9))
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()

# ─────────────────────────────── 출력 ───────────────────────────────

def setup_stdout() -> bool:
    """stdout 을 UTF-8 로 설정하고 기호(✔ ✘ ⚠) 출력 가능 여부를 돌려준다.

    cp949 등 기호를 담을 수 없는 인코딩이면 False — ASCII 대체 표기를 쓴다."""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # 3.7+
    except (AttributeError, OSError, ValueError):
        # 인코딩을 바꿀 수 없으면 인코딩 오류만 대체 문자로 처리한다.
        try:
            sys.stdout.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "✔✘⚠·━↳═→".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


class Style:
    """터미널이 아니면 색을 끈다 (파이프 출력에 제어문자가 섞이지 않게)."""

    # 기호를 못 쓰는 콘솔(cp949·cp437 등)에서 쓸 대체 표기
    ASCII = {"✔": "OK", "✘": "NG", "⚠": "!!", "·": "-",
             "━": "=", "↳": "->", "═": "=", "→": "=>"}

    def __init__(self, enabled: bool, unicode_ok: bool = True):
        self.on = enabled
        self.uni = unicode_ok
        self.RST = "\033[0m" if enabled else ""
        self.DIM = "\033[2m" if enabled else ""
        self.B = "\033[1m" if enabled else ""
        self.OKC = "\033[32m" if enabled else ""
        self.NGC = "\033[31m" if enabled else ""
        self.WNC = "\033[33m" if enabled else ""

    def g(self, ch: str) -> str:
        return ch if self.uni else Style.ASCII.get(ch, ch)

    @property
    def OK(self) -> str: return f"{self.OKC}{self.g('✔')}{self.RST}"
    @property
    def NG(self) -> str: return f"{self.NGC}{self.g('✘')}{self.RST}"
    @property
    def WN(self) -> str: return f"{self.WNC}{self.g('⚠')}{self.RST}"
    @property
    def IN(self) -> str: return f"{self.DIM}{self.g('·')}{self.RST}"


def width(s: str) -> int:
    """터미널 표시 폭. 전각 문자(한글·한자)는 2칸."""
    n = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        n += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return n


def pad(s: str, w: int) -> str:
    return s + " " * max(0, w - width(s))


def trunc(s: str, w: int) -> str:
    """표시 폭 기준으로 자른다."""
    if width(s) <= w:
        return s
    out, n = "", 0
    for ch in s:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if n + cw > w - 1:
            return out + "…"
        out += ch
        n += cw
    return out


# ─────────────────────────────── 결과 수집 ───────────────────────────────

CRIT, WARN, INFO = "CRIT", "WARN", "INFO"

# 계층 순서. 가장 얕은 계층의 CRIT 를 근본 원인으로 판정하고,
# 더 깊은 계층의 실패는 그 영향으로 처리한다.
LAYER_ORDER = ["L0", "L1", "L2", "L2b", "L2c", "L3", "L3b", "L4", "L4b",
               "L5", "L5b", "L6", "L6b", "L7", "L7b", "L8", "L9"]


@dataclass
class Finding:
    level: str
    layer: str
    message: str
    target: str = ""            # "" 은 공통 검사(L0·L1·L2·L9)
    code: str = ""              # 판정 로직용 분류값 (문구와 별개)


def layer_key(layer: str) -> int:
    return LAYER_ORDER.index(layer) if layer in LAYER_ORDER else 99


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    cur: str = ""               # 현재 검사 대상. add() 가 이 값으로 발견 사항을 묶는다.

    def add(self, level: str, layer: str, message: str, code: str = "") -> None:
        for f in self.findings:
            if f.target == self.cur and f.message == message:
                return
        self.findings.append(Finding(level, layer, message, self.cur, code))

    def scope(self, target: Optional[str] = None) -> list[Finding]:
        """그 대상의 발견 사항 + 공통 발견 사항. None 이면 전부."""
        if target is None:
            return list(self.findings)
        return [f for f in self.findings if f.target in ("", target)]

    def has_code(self, *codes: str, target: Optional[str] = None) -> bool:
        return any(f.code in codes for f in self.scope(target))

    def crit_layers(self, target: Optional[str] = None) -> list[str]:
        seen = {f.layer for f in self.scope(target) if f.level == CRIT}
        return sorted(seen, key=layer_key)


# ═══════════════════════════ 프록시 ═══════════════════════════
# 직접 경로와 프록시 경로를 각각 측정해 비교한다 (L2c).

@dataclass
class Proxy:
    scheme: str          # http | socks5 | socks5h | socks4
    host: str
    port: int
    user: Optional[str] = None
    password: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def remote_dns(self) -> bool:
        """프록시가 이름 해석을 하는지 여부. 이 경우 로컬 DNS 장애와 관계없이 접속된다."""
        return self.scheme in ("socks5h", "http")

    @staticmethod
    def parse(url: str) -> "Proxy":
        m = re.match(
            r"^(?:(?P<s>https?|socks5h?|socks4a?)://)?"
            r"(?:(?P<u>[^:@/]+)(?::(?P<p>[^@/]*))?@)?"
            r"(?P<h>\[[0-9a-fA-F:]+\]|[^:/@]+)"
            r"(?::(?P<port>\d+))?/?$", url)
        if not m:
            raise ValueError(f"프록시 주소 형식 오류: {url}")
        scheme = (m.group("s") or "http").replace("https", "http")
        host = m.group("h").strip("[]")
        port = int(m.group("port") or (1080 if scheme.startswith("socks") else 8080))
        return Proxy(scheme, host, port, m.group("u"), m.group("p"))


class ProxyError(Exception):
    """프록시 거부. 메시지에 프록시가 돌려준 사유(차단 페이지·정책 문구)를 담는다.

    status: 프록시가 목적지 연결 결과를 알려 준 경우의 TCP 상태 (UNREACH·REFUSED·TIMEOUT).
    기본값은 PROXY_DENY (프록시 정책·인증)."""

    def __init__(self, msg: str, status: str = "PROXY_DENY"):
        super().__init__(msg)
        self.status = status


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """n 바이트를 모두 읽는다. 연결이 먼저 끊기면 읽은 만큼만 돌려준다."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _proxy_http_connect(sock: socket.socket, px: Proxy, host: str, port: int) -> None:
    req = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}",
           "Proxy-Connection: keep-alive", f"User-Agent: netcheck/{VERSION}"]
    if px.user is not None:
        cred = base64.b64encode(f"{px.user}:{px.password or ''}".encode()).decode()
        req.append(f"Proxy-Authorization: Basic {cred}")
    sock.sendall(("\r\n".join(req) + "\r\n\r\n").encode())

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ProxyError("프록시가 응답 없이 연결을 끊음")
        buf += chunk
        if len(buf) > 65536:
            break
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    status = head.split("\r\n", 1)[0]
    parts = status.split(None, 2)
    code = parts[1] if len(parts) > 1 else "?"
    if code != "200":
        # 407: 인증 요구, 403: 정책 차단
        reason = parts[2] if len(parts) > 2 else ""
        # 502·503: 프록시가 목적지에 연결 실패, 504: 목적지 응답 시간 초과
        st = {"502": "UNREACH", "503": "UNREACH", "504": "TIMEOUT"}.get(code, "PROXY_DENY")
        raise ProxyError(f"CONNECT 거부 {code} {reason}".strip(), st)


def _proxy_socks5(sock: socket.socket, px: Proxy, host: str, port: int,
                  resolve_locally: bool) -> None:
    methods = b"\x00" + (b"\x02" if px.user is not None else b"")
    sock.sendall(bytes([5, len(methods)]) + methods)
    rep = recv_exact(sock, 2)
    if len(rep) < 2 or rep[0] != 5:
        raise ProxyError("SOCKS5 핸드셰이크 응답 없음 (SOCKS 프록시가 아닐 수 있음)")
    if rep[1] == 0xFF:
        raise ProxyError("SOCKS5 인증 방식 거부됨")
    if rep[1] == 2:
        if px.user is None:
            raise ProxyError("SOCKS5 인증 필요 — 자격증명 없음")
        u, p = px.user.encode(), (px.password or "").encode()
        sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        ar = recv_exact(sock, 2)
        if len(ar) < 2 or ar[1] != 0:
            raise ProxyError("SOCKS5 인증 실패")

    if resolve_locally:
        try:
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            packed = socket.inet_pton(fam, host)
            atyp, addr = (1, packed) if fam == socket.AF_INET else (4, packed)
        except OSError:
            atyp, addr = 3, bytes([len(host)]) + host.encode()
    else:
        atyp, addr = 3, bytes([len(host)]) + host.encode()

    sock.sendall(bytes([5, 1, 0, atyp]) + addr + struct.pack("!H", port))
    r = recv_exact(sock, 4)
    if len(r) < 4:
        raise ProxyError("SOCKS5 응답이 잘림")
    codes = {1: "일반 실패", 2: "정책상 거부", 3: "망 도달 불가", 4: "호스트 도달 불가",
             5: "연결 거부(RST)", 6: "TTL 만료", 7: "명령 미지원", 8: "주소 형식 미지원"}
    if r[1] != 0:
        # 3·4: 도달 불가, 5: RST, 6: TTL 만료(시간 초과) — 목적지 상태. 그 외는 프록시 정책.
        st = {3: "UNREACH", 4: "UNREACH", 5: "REFUSED", 6: "TIMEOUT"}.get(r[1], "PROXY_DENY")
        raise ProxyError(f"SOCKS5 거부: {codes.get(r[1], r[1])}", st)
    # 응답의 바인딩 주소 필드까지 읽어야 이후 스트림이 맞는다.
    if r[3] == 1:
        recv_exact(sock, 4 + 2)
    elif r[3] == 4:
        recv_exact(sock, 16 + 2)
    elif r[3] == 3:
        ln = recv_exact(sock, 1)
        if ln:
            recv_exact(sock, ln[0] + 2)


def _proxy_socks4(sock: socket.socket, px: Proxy, host: str, port: int) -> None:
    try:
        ip = socket.inet_aton(host)
        name = b""
    except OSError:
        ip, name = b"\x00\x00\x00\x01", host.encode() + b"\x00"   # SOCKS4a
    uid = (px.user or "").encode() + b"\x00"
    sock.sendall(b"\x04\x01" + struct.pack("!H", port) + ip + uid + name)
    r = recv_exact(sock, 8)
    if len(r) < 2 or r[1] != 0x5A:
        raise ProxyError(f"SOCKS4 거부: {r[1] if len(r) > 1 else '무응답'}")


def open_stream(host: str, port: int, timeout: float,
                proxy: Optional[Proxy] = None,
                source_ip: Optional[str] = None, tunnel: bool = True) -> socket.socket:
    """목적지까지 TCP 스트림을 연다. 프록시가 있으면 프록시 터널을 쓴다.

    source_ip: 출발지 주소 고정 (회선별 측정용).
    tunnel=False: 프록시에 연결만 하고 CONNECT 는 하지 않음 (HTTP 프록시로 GET 요청용).
    """
    dst_host, dst_port = (proxy.host, proxy.port) if proxy else (host, port)
    infos = socket.getaddrinfo(dst_host, dst_port, 0, socket.SOCK_STREAM)
    last: Optional[Exception] = None
    for fam, stype, proto, _canon, sa in infos:
        s = socket.socket(fam, stype, proto)
        s.settimeout(timeout)
        try:
            if source_ip:
                s.bind((source_ip, 0))
            s.connect(sa)
            if proxy and tunnel:
                if proxy.scheme == "http":
                    _proxy_http_connect(s, proxy, host, port)
                elif proxy.scheme.startswith("socks5"):
                    _proxy_socks5(s, proxy, host, port,
                                  resolve_locally=(proxy.scheme == "socks5"))
                else:
                    _proxy_socks4(s, proxy, host, port)
            return s
        except Exception as ex:
            last = ex
            s.close()
    raise last if last else OSError("연결할 주소 없음")


# ═══════════════════════ TCP 연결 검사 ═══════════════════════
# TCP 연결 실패 유형. 유형에 따라 차단 주체가 다르다.

OPEN, TIMEOUT, REFUSED, UNREACH, RESET, PROXY_DENY, LOCAL, ERROR = (
    "OPEN", "TIMEOUT", "REFUSED", "UNREACH", "RESET", "PROXY_DENY", "LOCAL", "ERROR")

WHY = {
    OPEN:       "연결됨",
    TIMEOUT:    "무응답 — 패킷 드롭",
    REFUSED:    "RST 수신 — 호스트 응답, 포트 닫힘",
    UNREACH:    "ICMP 도달 불가 — 라우터가 경로 없음 응답",
    RESET:      "연결 직후 끊김 — 중간 장비 개입 의심",
    PROXY_DENY: "프록시 거부",
    LOCAL:      "로컬 차단 — 이 기기의 방화벽·보안 SW",
    ERROR:      "프로브 오류",
}


@dataclass
class TcpResult:
    status: str
    ms: int
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == OPEN


def tcp_probe(host: str, port: int, timeout: float,
              proxy: Optional[Proxy] = None,
              source_ip: Optional[str] = None) -> TcpResult:
    t0 = time.monotonic()
    ms = lambda: int((time.monotonic() - t0) * 1000)
    if not (1 <= port <= 65535):
        return TcpResult(ERROR, 0, "포트 범위 밖")
    s = None
    try:
        s = open_stream(host, port, timeout, proxy, source_ip)
        return TcpResult(OPEN, ms())
    except ProxyError as ex:
        return TcpResult(ex.status, ms(), str(ex))
    except socket.timeout:
        return TcpResult(TIMEOUT, ms(), "no-response")
    except socket.gaierror as ex:
        return TcpResult(ERROR, ms(), f"이름 해석 실패({ex.strerror or ex})")
    except OSError as ex:
        n = ex.errno
        name = E.errorcode.get(n, str(n))
        if n == E.ECONNREFUSED:
            return TcpResult(REFUSED, ms(), name)
        if n in (E.EHOSTUNREACH, E.ENETUNREACH):
            return TcpResult(UNREACH, ms(), name)
        if n == E.ECONNRESET:
            return TcpResult(RESET, ms(), name)
        if n == E.ETIMEDOUT:
            return TcpResult(TIMEOUT, ms(), name)
        if n in (E.EPERM, E.EACCES):          # 로컬 방화벽(netfilter OUTPUT·콘텐츠 필터)
            return TcpResult(LOCAL, ms(), name)
        if n in (E.EADDRNOTAVAIL, E.EADDRINUSE):
            return TcpResult(ERROR, ms(), f"출발지 바인딩 실패({name})")
        return TcpResult(ERROR, ms(), name)
    finally:
        if s is not None:
            s.close()


@dataclass
class TcpSeries:
    tries: int
    ok: int
    times: list[int]
    last_fail: Optional[TcpResult]

    @property
    def status(self) -> str:
        if self.ok:
            return OPEN
        return self.last_fail.status if self.last_fail else ERROR

    @property
    def detail(self) -> str:
        return self.last_fail.detail if (self.last_fail and not self.ok) else ""

    @property
    def flaky(self) -> bool:
        return 0 < self.ok < self.tries

    def stats(self) -> tuple[int, int, int]:
        if not self.times:
            return (0, 0, 0)
        return (min(self.times), sum(self.times) // len(self.times), max(self.times))


def tcp_series(host: str, port: int, timeout: float, tries: int,
               interval: float = 0.0, proxy: Optional[Proxy] = None,
               source_ip: Optional[str] = None,
               abort: Optional[Callable[[], None]] = None) -> TcpSeries:
    """여러 번 측정해 간헐 장애를 확인한다.

    abort: 반복 사이와 대기 중에 호출해 중단 요청을 확인한다."""
    times, ok, last_fail = [], 0, None
    for i in range(tries):
        if abort:
            abort()
        if i and interval:
            # 대기를 짧게 나눠 중단 요청을 바로 반영한다.
            slept = 0.0
            while slept < interval:
                time.sleep(min(0.25, interval - slept))
                slept += 0.25
                if abort:
                    abort()
        r = tcp_probe(host, port, timeout, proxy, source_ip)
        if r.ok:
            ok += 1
            times.append(r.ms)
        else:
            last_fail = r
    return TcpSeries(tries, ok, times, last_fail)


def tcp_mss(ip: str, port: int, timeout: float = 4.0,
            proxy: Optional[Proxy] = None) -> Optional[int]:
    """연결에서 합의된 MSS 를 읽는다.

    ICMP 와 무관하게 얻을 수 있어 PMTU 탐색(L8)이 막힌 망에서도 쓸 수 있다.
    중간 장비의 MSS clamping 여부도 이 값으로 확인한다."""
    if proxy:
        return None                     # 프록시 연결의 MSS 는 목적지 경로와 무관
    try:
        s = open_stream(ip, port, timeout)
    except Exception:
        return None
    try:
        return s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    except OSError:
        return None
    finally:
        s.close()


# ═══════════════ 경로 출처 검증 (RPKI) ═══════════════
# RPKI: 광고 AS 가 해당 대역의 정당한 광고자인지 확인한다 (경로 하이재킹 탐지).

def rpki_validate(asn: str, prefix: str, timeout: float,
                  proxy: Optional[Proxy] = None) -> tuple[str, str]:
    """(상태, 설명). 상태는 valid | invalid | unknown | 조회실패."""
    if not asn or not prefix or asn in ("-", "NA") or "/" not in prefix:
        return "조회실패", "AS·대역 정보 없음"
    host = "stat.ripe.net"
    try:
        ans = resolve_system(host)
        ip = ans.addrs[0] if ans.addrs else ""
        if not ip or is_sinkhole(ip):
            doh = doh_query(host, "A", timeout, proxy)
            ip = doh.addrs[0] if doh and doh.addrs else ""
        if not ip:
            return "조회실패", "stat.ripe.net 이름 해석 실패"
        code, body = https_get(
            host, ip,
            f"/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}",
            max(timeout, 10), {"Accept": "application/json"}, proxy)
        if code != 200:
            return "조회실패", f"HTTP {code}"
        j = json.loads(body[body.find(b"{"):body.rfind(b"}") + 1])
        d = j.get("data") or {}
        return str(d.get("status") or "unknown"), str(d.get("description") or "")
    except Exception as ex:
        return "조회실패", f"{type(ex).__name__}"


def tcp_ttl_distance(ip: str, port: int, timeout: float = 2.0,
                     max_ttl: int = 32) -> Optional[int]:
    """SYN 의 TTL 을 바꿔 가며 목적지까지 홉 수를 잰다. root 불필요.

    연결이 성립하는 최소 TTL 이 거리. ICMP·UDP traceroute 가 막힌 망에서도 동작한다.
    traceroute 거리보다 현저히 짧으면 중간 장비의 대리 응답으로 판단한다.
    """
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    lvl, opt = ((socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS)
                if fam == socket.AF_INET6 else (socket.IPPROTO_IP, socket.IP_TTL))

    def reaches(ttl: int) -> bool:
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.setsockopt(lvl, opt, ttl)
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
        except OSError:
            return False
        finally:
            s.close()

    if reaches(1):
        return 1
    hi = 2
    while hi <= max_ttl and not reaches(hi):
        hi *= 2
    if hi > max_ttl:
        return None
    lo = hi // 2                      # lo: 실패, hi: 성공 — 이분 탐색
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if reaches(mid):
            hi = mid
        else:
            lo = mid
    return hi


# ═══════════════════════ 주소 분류 ═══════════════════════
# 구간 구분 기준: 홉 번호가 아니라 주소 종류와 소유자.

_CLASSES: list[tuple[str, str]] = [
    (r"^10\.", "사설(RFC1918)"),
    (r"^192\.168\.", "사설(RFC1918)"),
    (r"^172\.(1[6-9]|2\d|3[01])\.", "사설(RFC1918)"),
    (r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.", "CGNAT(RFC6598)"),
    (r"^169\.254\.", "링크로컬 — DHCP 실패"),
    (r"^127\.", "루프백"),
    (r"^0\.0\.0\.0$", "널 — 싱크홀"),
    (r"^(22[4-9]|23\d)\.", "멀티캐스트"),
    (r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.", "문서용(RFC5737)"),
    (r"^198\.1[89]\.", "벤치마크(RFC2544)"),
    (r"^192\.0\.0\.", "IETF 예약"),
    (r"^(2[4-9]\d|25[0-5])\.", "예약(RFC1112)"),
    (r"^fe80:", "링크로컬 v6"),
    (r"^f[cd][0-9a-f]{2}:", "ULA v6"),
    (r"^::1$", "루프백 v6"),
    (r"^::$", "널 v6 — 싱크홀"),
    (r"^::ffff:", "v4 매핑"),
    (r"^64:ff9b:", "NAT64"),
    (r"^2002:", "6to4"),
]

NOT_ROUTABLE = ("문서용", "벤치마크", "예약", "IETF", "멀티캐스트", "링크로컬")


def ip_class(ip: str) -> str:
    low = ip.lower()
    for pat, name in _CLASSES:
        if re.match(pat, low):
            return name
    return "공인"


def is_private(ip: str) -> bool:
    return ip_class(ip) != "공인"


def is_sinkhole(ip: str) -> bool:
    return ip in ("0.0.0.0", "::", "::1") or ip.startswith("127.")


def normalize_host(h: str) -> tuple[str, str]:
    """(정규화된 이름, 오류 메시지). 국제화 이름은 punycode 로 변환한다.

    DNS 이름 규칙 위반을 미리 검사해 인코딩 단계의 예외를 막는다."""
    h = h.strip().rstrip(".")
    if not h:
        return "", "이름이 비어 있음"
    if is_ip_literal(h):
        return h, ""
    if any(ord(c) > 127 for c in h):
        try:
            h = h.encode("idna").decode("ascii")
        except (UnicodeError, ValueError) as ex:
            return "", f"국제화 이름을 punycode 로 변환할 수 없음 ({ex})"
    if re.search(r"[^A-Za-z0-9._-]", h):
        bad = "".join(sorted(set(re.findall(r"[^A-Za-z0-9._-]", h))))
        return "", f"호스트 이름에 허용되지 않는 문자: {bad!r}"
    if len(h) > 253:
        return "", f"이름이 너무 김 ({len(h)}자, 최대 253)"
    for lab in h.split("."):
        if not lab:
            return "", "빈 라벨 있음 (점 연속)"
        if len(lab) > 63:
            return "", f"라벨 63자 초과 ({len(lab)}자): {lab[:24]}…"
        if lab.startswith("-") or lab.endswith("-"):
            return "", f"라벨이 하이픈으로 시작하거나 끝남: {lab}"
    return h, ""


def is_ip_literal(s: str) -> bool:
    """IP 주소 리터럴 여부. IPv6 에는 a~f 가 포함되므로 문자 포함 여부로 판단하지 않는다."""
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, s)
            return True
        except OSError:
            pass
    return False


# ═══════════════════════ DNS ═══════════════════════
# DNS 질의를 직접 구성한다 (dig 미사용). rcode·TTL·CNAME 체인을 얻고
# 무응답과 NXDOMAIN 을 구분한다.

RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
         4: "NOTIMP", 5: "REFUSED"}
QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "AAAA": 28}


@dataclass
class DnsAnswer:
    rcode: str = "TIMEOUT"
    addrs: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)   # NS/PTR 답
    ttl: Optional[int] = None
    ms: int = 0
    truncated: bool = False
    authentic: bool = False        # AD 플래그 — 해석기의 DNSSEC 검증 완료

def _dns_encode(name: str, qtype: int, qid: int) -> bytes:
    labels = []
    for l in name.rstrip(".").split("."):
        if not l:
            continue
        b = l.encode("ascii", "ignore") if l.isascii() else l.encode("idna")
        labels.append(bytes([len(b)]) + b)
    q = b"".join(labels) + b"\x00"
    # RD(재귀) + AD. AD 를 설정해야 응답에 DNSSEC 검증 여부가 표시된다.
    return struct.pack("!HHHHHH", qid, 0x0120, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def _dns_name(buf: bytes, off: int) -> tuple[str, int]:
    """압축 포인터를 따라 이름을 읽는다. 루프 방지를 위해 횟수를 제한한다."""
    labels, jumped, end, guard = [], False, off, 0
    while True:
        guard += 1
        if guard > 128 or off >= len(buf):
            break
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off = True, ptr
            continue
        labels.append(buf[off + 1:off + 1 + n].decode("latin-1"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def _dns_parse(buf: bytes) -> DnsAnswer:
    """DNS 응답 파싱. 잘리거나 손상된 패킷은 읽은 부분까지만 반영한다."""
    a = DnsAnswer()
    try:
        _dns_parse_into(a, buf)
    except (struct.error, ValueError, IndexError):
        pass
    return a


def _dns_parse_into(a: DnsAnswer, buf: bytes) -> None:
    if len(buf) < 12:
        return
    _qid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", buf[:12])
    a.rcode = RCODE.get(flags & 0xF, f"RCODE{flags & 0xF}")
    a.truncated = bool(flags & 0x0200)
    a.authentic = bool(flags & 0x0020)      # AD (Authenticated Data)
    off = 12
    for _ in range(qd):
        _n, off = _dns_name(buf, off)
        off += 4
    for _ in range(an):
        _n, off = _dns_name(buf, off)
        if off + 10 > len(buf):
            break
        rtype, _cls, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rd = buf[off:off + rdlen]
        if len(rd) < rdlen:
            break
        if a.ttl is None:
            a.ttl = ttl
        if rtype == 1 and rdlen == 4:
            a.addrs.append(socket.inet_ntop(socket.AF_INET, rd))
        elif rtype == 28 and rdlen == 16:
            a.addrs.append(socket.inet_ntop(socket.AF_INET6, rd))
        elif rtype == 5:
            a.cnames.append(_dns_name(buf, off)[0])
        elif rtype in (2, 12):
            a.names.append(_dns_name(buf, off)[0])
        off += rdlen


def dns_query(name: str, qtype: str, server: str, timeout: float = 2.0) -> DnsAnswer:
    qid = int.from_bytes(os.urandom(2), "big")
    pkt = _dns_encode(name, QTYPE[qtype], qid)
    t0 = time.monotonic()
    fam = socket.AF_INET6 if ":" in server else socket.AF_INET
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (server, 53))
            while True:                      # 다른 질의 ID 의 응답(지연·위조)은 버림
                data, _ = s.recvfrom(4096)
                if data[:2] == pkt[:2]:
                    break
        finally:
            s.close()
    except (socket.timeout, OSError):
        return DnsAnswer(ms=int((time.monotonic() - t0) * 1000))
    ans = _dns_parse(data)
    ans.ms = int((time.monotonic() - t0) * 1000)
    # TC(잘림) 플래그면 TCP 로 재질의한다.
    if ans.truncated:
        try:
            with socket.create_connection((server, 53), timeout) as t:
                t.sendall(struct.pack("!H", len(pkt)) + pkt)
                head = recv_exact(t, 2)
                if len(head) == 2:
                    body = recv_exact(t, struct.unpack("!H", head)[0])
                    ans2 = _dns_parse(body)
                    if ans2.rcode != "TIMEOUT":
                        ans2.ms = int((time.monotonic() - t0) * 1000)
                        return ans2
        except OSError:
            pass
    return ans


def win_resolvers() -> list[str]:
    """레지스트리에서 DNS 서버를 읽는다 (ipconfig 출력은 번역되므로 쓰지 않음)."""
    found: list[str] = []
    try:
        import winreg
        base = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                try:
                    with winreg.OpenKey(k, winreg.EnumKey(k, i)) as sub:
                        for name in ("NameServer", "DhcpNameServer"):
                            try:
                                v = winreg.QueryValueEx(sub, name)[0]
                            except OSError:
                                continue
                            for ip in re.split(r"[,\s]+", str(v).strip()):
                                if ip and is_ip_literal(ip) and ip not in found:
                                    found.append(ip)
                except OSError:
                    continue
    except Exception:
        pass
    return found


def system_resolvers() -> list[str]:
    out: list[str] = []
    if IS_WIN:
        return win_resolvers()
    if IS_MAC:
        try:
            txt = subprocess.run(["scutil", "--dns"], capture_output=True,
                                 text=True, timeout=5).stdout
            out = re.findall(r"nameserver\[0\]\s*:\s*(\S+)", txt)
        except Exception:
            pass
    if not out:
        try:
            with open("/etc/resolv.conf") as fh:
                out = re.findall(r"^nameserver\s+(\S+)", fh.read(), re.M)
        except OSError:
            pass
    # 순서 유지 중복 제거 (첫 항목이 실제 사용 서버)
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def resolve_system(name: str, want6: bool = False) -> DnsAnswer:
    """시스템 DNS 서버로 질의한다. 서버를 찾지 못하면 OS 해석기를 쓴다."""
    for srv in system_resolvers():
        a = dns_query(name, "AAAA" if want6 else "A", srv)
        if a.rcode != "TIMEOUT":
            return a
    try:
        fam = socket.AF_INET6 if want6 else socket.AF_INET
        infos = socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
        return DnsAnswer("NOERROR", sorted({i[4][0] for i in infos}))
    except socket.gaierror as ex:
        return DnsAnswer("NXDOMAIN" if ex.errno == socket.EAI_NONAME else "TIMEOUT")


def os_resolve(host: str, want6: bool = False) -> list[str]:
    """OS 해석기(getaddrinfo) 결과. hosts 파일·도메인별 DNS(VPN 분할 DNS)·mDNS 가 반영된 값."""
    fam = socket.AF_INET6 if want6 else socket.AF_INET
    try:
        res = socket.getaddrinfo(host, None, fam, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return []
    return list(dict.fromkeys(r[4][0].split("%")[0] for r in res))


FILTER_CNAME = re.compile(r"forcesafesearch|restrict|sinkhole|block|warning|filter", re.I)


# ═══════════════════════ DoH ═══════════════════════
# DoH: 평문 DNS(53) 가로채기 여부를 비교하기 위한 대조군.
# DoH 서버 이름 해석도 조작될 수 있으므로 IP 로 접속한다.

DOH_SERVERS = [("cloudflare-dns.com", "1.1.1.1"), ("dns.google", "8.8.8.8")]


def https_get(host: str, ip: str, path: str, timeout: float,
              headers: Optional[dict] = None,
              proxy: Optional[Proxy] = None) -> tuple[int, bytes]:
    """SNI 와 Host 는 host 로, 실제 연결은 ip 로. curl --resolve 와 같은 동작."""
    ctx = ssl.create_default_context()
    raw = open_stream(ip, 443, timeout, proxy)
    sec = None
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            sec = s
            s.settimeout(timeout)
            hdr = {"Host": host, "Connection": "close",
                   "User-Agent": f"netcheck/{VERSION}"}
            hdr.update(headers or {})
            req = f"GET {path} HTTP/1.1\r\n" + \
                  "".join(f"{k}: {v}\r\n" for k, v in hdr.items()) + "\r\n"
            s.sendall(req.encode())
            buf = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1 << 20:
                    break
    finally:
        for h in (sec, raw):
            if h is not None:
                try:
                    h.close()
                except OSError:
                    pass
    head, _, body = buf.partition(b"\r\n\r\n")
    first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    code = int(first.split()[1]) if len(first.split()) > 1 and first.split()[1].isdigit() else 0
    if re.search(rb"(?im)^transfer-encoding:\s*chunked", head):
        body = dechunk(body)
    return code, body


def dechunk(body: bytes) -> bytes:
    """chunked 전송 인코딩을 푼다. 풀지 않으면 길이 표시가 섞여 JSON 파싱이 실패한다."""
    out, pos = bytearray(), 0
    while pos < len(body):
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            break
        try:
            size = int(body[pos:nl].split(b";")[0].strip(), 16)
        except ValueError:
            # chunked 형식이 아니면 나머지를 그대로 쓴다.
            return bytes(out) + body[pos:] if out else body
        if size == 0:
            break
        out += body[nl + 2: nl + 2 + size]
        pos = nl + 2 + size + 2
    return bytes(out)


def doh_query(name: str, qtype: str, timeout: float,
              proxy: Optional[Proxy] = None) -> Optional[DnsAnswer]:
    for host, ip in DOH_SERVERS:
        try:
            code, body = https_get(
                host, ip, f"/dns-query?name={name}&type={qtype}", timeout,
                {"accept": "application/dns-json"}, proxy)
            if code != 200:
                continue
            # chunked 길이 표시를 피해 JSON 부분만 꺼낸다.
            start = body.find(b"{")
            end = body.rfind(b"}")
            if start < 0 or end < 0:
                continue
            j = json.loads(body[start:end + 1])
            ans = DnsAnswer(RCODE.get(j.get("Status", 0), str(j.get("Status"))))
            for rr in j.get("Answer", []) or []:
                if rr.get("type") in (1, 28):
                    ans.addrs.append(rr["data"])
                    if ans.ttl is None:
                        ans.ttl = rr.get("TTL")
                elif rr.get("type") == 5:
                    ans.cnames.append(rr["data"].rstrip("."))
            return ans
        except Exception:
            continue
    return None


# ═══════════════════════ whois ═══════════════════════
# 홉·목적지 IP 의 AS·소유자 조회 (ISP 구간 구분용).

def whois_raw(query: str, server: str, timeout: float = 8.0) -> str:
    try:
        with socket.create_connection((server, 43), timeout) as s:
            s.settimeout(timeout)
            s.sendall((query + "\r\n").encode())
            out = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                out += chunk
                if len(out) > 1 << 20:
                    break
        return out.decode("utf-8", "replace")
    except OSError:
        return ""


@dataclass
class IpMeta:
    ip: str
    asn: str = "-"
    prefix: str = "-"
    cc: str = "-"
    registry: str = "-"
    allocated: str = "-"
    as_name: str = ""
    ptr: str = ""

    @property
    def routed(self) -> bool:
        return self.asn not in ("-", "NA", "")

    @property
    def short_name(self) -> str:
        """'EXAMPLE-AS - Example Net Co Ltd, KR' → 'Example Net Co Ltd'"""
        n = re.sub(r"^[^ ]+ - ", "", self.as_name)
        return re.sub(r", [A-Z]{2}$", "", n)


class MetaSet(dict):
    """조회 결과. ok=False 는 '결과 없음'이 아니라 '조회 실패'.
    whois 장애 시 모든 주소를 'BGP 미광고'로 오판하지 않도록 구분한다."""

    def __init__(self, *a, ok: bool = True, **kw):
        super().__init__(*a, **kw)
        self.ok = ok


def cymru_bulk(ips: Iterable[str], timeout: float = 10.0) -> MetaSet:
    """여러 IP 를 한 번의 접속으로 조회한다 (Cymru bulk whois)."""
    pub = [ip for ip in dict.fromkeys(ips) if not is_private(ip)]
    out = MetaSet()
    if not pub:
        return out
    body = "begin\nverbose\n" + "\n".join(pub) + "\nend\n"
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout) as s:
            s.settimeout(timeout)
            s.sendall(body.encode())
            buf = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                buf += chunk
        text = buf.decode("utf-8", "replace")
    except OSError:
        text = ""
    if not text.strip():
        out.ok = False
        return out
    for line in text.splitlines():
        cols = [c.strip() for c in line.split("|")]
        if len(cols) < 7 or cols[0] in ("AS", "Bulk mode; whois.cymru.com [2005-08-02]"):
            continue
        ip = cols[1]
        out[ip] = IpMeta(ip, cols[0] or "-", cols[2] or "-", cols[3] or "-",
                         cols[4] or "-", cols[5] or "-", cols[6] or "")
    return out


def ripe_netinfo(ip: str, timeout: float = 12.0,
                 proxy: Optional[Proxy] = None) -> Optional[IpMeta]:
    """RIPE stat 으로 IP 의 AS·대역을 조회한다. Cymru 조회 실패 시 목적지 조회용."""
    host = "stat.ripe.net"
    try:
        ans = resolve_system(host)
        sip = ans.addrs[0] if ans.addrs else ""
        if not sip or is_sinkhole(sip):
            doh = doh_query(host, "A", timeout, proxy)
            sip = doh.addrs[0] if doh and doh.addrs else ""
        if not sip:
            return None
        code, body = https_get(host, sip,
                               f"/data/network-info/data.json?resource={ip}",
                               timeout, {"Accept": "application/json"}, proxy)
        if code != 200:
            return None
        j = json.loads(body[body.find(b"{"):body.rfind(b"}") + 1])
        d = j.get("data") or {}
        asns = d.get("asns") or []
        if not asns:
            return None
        return IpMeta(ip, str(asns[0]), d.get("prefix") or "-", "-", "-", "-", "")
    except Exception:
        return None


RIR_HINTS = {"apnic": "whois.apnic.net", "arin": "whois.arin.net",
             "ripencc": "whois.ripe.net", "ripe": "whois.ripe.net",
             "lacnic": "whois.lacnic.net", "afrinic": "whois.afrinic.net"}


def rir_lookup(ip: str, registry: str, timeout: float = 8.0) -> dict[str, str]:
    """RIR whois 등록 정보 (조직·국가·abuse 연락처).
    whois 는 큰 블록부터 작은 블록 순으로 주므로 마지막(가장 구체적인) 값을 쓴다."""
    server = RIR_HINTS.get(registry.lower(), "whois.arin.net")
    txt = whois_raw(("n + " + ip) if "arin" in server else ip, server, timeout)
    if not txt.strip():
        txt = whois_raw(ip, "whois.iana.org", timeout)
    want = {
        "netname": r"^(?:netname|NetName)\s*:\s*(.+)$",
        "org": r"^(?:descr|org-name|orgname|OrgName|organisation|Organization)\s*:\s*(.+)$",
        "country": r"^(?:country|Country)\s*:\s*(.+)$",
        "range": r"^(?:inetnum|inet6num|NetRange|CIDR)\s*:\s*(.+)$",
        "abuse": r"^(?:abuse-mailbox|OrgAbuseEmail|abuse-c)\s*:\s*(.+)$",
    }
    got: dict[str, str] = {}
    for key, pat in want.items():
        hits = re.findall(pat, txt, re.M | re.I)
        if hits:
            got[key] = hits[-1].strip()
    return got


def ptr_lookup(ip: str, timeout: float = 2.0) -> str:
    """역방향 DNS. 라우터 PTR 에는 도시·역할·회선 정보가 들어 있는 경우가 있다."""
    if is_private(ip) or ":" in ip:
        return ""
    arpa = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    for srv in (system_resolvers() or ["1.1.1.1"]) + ["1.1.1.1"]:
        a = dns_query(arpa, "PTR", srv, timeout)
        if a.names:
            return a.names[0].rstrip(".")
        if a.rcode == "NXDOMAIN":
            return ""
    return ""


def ip_kind(meta: IpMeta) -> str:
    """AS·조직 이름 기반 분류 (참고용)."""
    n = f"{meta.as_name} {meta.ptr}".lower()
    table = [
        (("cloudflare",), "CDN — Cloudflare"),
        (("akamai",), "CDN — Akamai"),
        (("fastly",), "CDN — Fastly"),
        (("cloudfront", "amazon", "aws"), "클라우드 — AWS"),
        (("google", "gcp"), "클라우드 — Google"),
        (("microsoft", "azure"), "클라우드 — Azure"),
        (("alibaba", "aliyun"), "클라우드 — Alibaba"),
        (("oracle",), "클라우드 — Oracle"),
        (("digitalocean", "linode", "vultr", "hetzner", "ovh"), "VPS 호스팅"),
        (("cdnetworks", "kinx", "cachefly", "edgecast", "bunny"), "CDN·IX"),
        (("naver", "kakao", "nhn"), "국내 플랫폼"),
        (("national", "government", "ministry", "go.kr", "nirs"), "공공·정부망"),
        (("univ", "ac.kr", "edu", "research"), "학술·연구망"),
        (("broadband", "telecom", "kt corp", "dacom", "skb"), "통신사망"),
    ]
    for keys, label in table:
        if any(k in n for k in keys):
            return label
    return "일반 호스팅·자체 운영"


# ═══════════════════════ TLS ═══════════════════════

@dataclass
class TlsInfo:
    ok: bool = False
    error: str = ""
    version: str = ""
    cipher: str = ""
    alpn: str = ""
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    sans: list[str] = field(default_factory=list)
    verified: bool = False
    name_match: Optional[bool] = None
    sni_blocked: bool = False
    serial: str = ""
    not_before: str = ""


# TLS 검사(가로채기) 제품의 발급자 이름. 미등록 CA 를 의심하는 대신 알려진 제품명을 찾는다.
MITM_VENDORS = ("fortinet", "fortigate", "palo alto", "zscaler", "netskope",
                "blue coat", "bluecoat", "sophos", "kaspersky", "bitdefender",
                "eset", "avast", "mcafee", "trend micro", "websense",
                "forcepoint", "check point", "checkpoint", "umbrella",
                "mitmproxy", "charles", "fiddler", "burp")


def decode_peer_cert(der: Optional[bytes]) -> dict:
    """DER 인증서를 dict 로 변환한다.

    검증을 끈 소켓은 getpeercert() 가 빈 값을 주므로 ssl 내부 디코더를 쓴다.
    비공개 API 이므로 실패하면 빈 dict 를 돌려준다."""
    if not der:
        return {}
    import tempfile
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)      # type: ignore[attr-defined]
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    except Exception:
        return {}


def _dn(seq) -> str:
    parts = []
    for rdn in seq or ():
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def tls_probe(host: str, ip: str, port: int, timeout: float,
              proxy: Optional[Proxy] = None, sni: bool = True) -> TlsInfo:
    info = TlsInfo()
    ctx = ssl.create_default_context()
    if not sni:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass
    # 검증 실패 시에도 만료·이름 불일치를 보고하려면 인증서 내용이 필요하다.
    lax = ssl.create_default_context()
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    try:
        lax.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    # 1차: 검증 연결. 일시 오류(타임아웃·리셋)는 같은 설정으로 한 번 더 시도하고,
    # 인증서 검증 실패일 때만 검증 없이 다시 연결해 인증서 내용을 읽는다.
    plan = [(1, ctx), (1, ctx)]
    while plan:
        attempt, context = plan.pop(0)
        raw = sec = None
        try:
            raw = open_stream(ip, port, timeout, proxy)
            kw = {"server_hostname": host} if sni else {}
            with context.wrap_socket(raw, **kw) as s:
                sec = s
                s.settimeout(timeout)
                info.ok = True
                info.verified = (attempt == 1 and sni)
                info.version = s.version() or ""
                c = s.cipher()
                info.cipher = c[0] if c else ""
                info.alpn = s.selected_alpn_protocol() or ""
                cert = s.getpeercert()
                if not cert:
                    # 검증을 끄면 getpeercert() 가 빈 값을 주므로 DER 를 직접 디코드한다.
                    cert = decode_peer_cert(s.getpeercert(binary_form=True))
                if cert:
                    info.subject = _dn(cert.get("subject"))
                    info.issuer = _dn(cert.get("issuer"))
                    info.not_after = cert.get("notAfter", "")
                    info.not_before = cert.get("notBefore", "")
                    info.serial = str(cert.get("serialNumber", ""))
                    info.sans = [v for k, v in cert.get("subjectAltName", ())
                                 if k in ("DNS", "IP Address")]
                    if info.not_after:
                        try:
                            exp = ssl.cert_time_to_seconds(info.not_after)
                            info.days_left = int((exp - time.time()) // 86400)
                        except ValueError:
                            pass
                    if info.sans:
                        info.name_match = _name_matches(host, info.sans)
                return info
        except ssl.SSLCertVerificationError as ex:
            info.error = str(ex.verify_message or ex)
            plan = [(2, lax)]          # 검증 없이 재시도 (인증서 내용 확보용)
            continue
        except ProxyError as ex:
            info.error = f"프록시 거부: {ex}"
            return info
        except (ssl.SSLError, OSError) as ex:
            if attempt == 2:           # 인증서 확보용 재시도 실패: 검증 실패 사유 유지
                return info
            info.error = str(ex) or type(ex).__name__
            continue
        finally:
            for h in (sec, raw):
                if h is not None:
                    try:
                        h.close()
                    except OSError:
                        pass
    return info


def _name_matches(host: str, sans: list[str]) -> bool:
    if is_ip_literal(host):
        return host in sans
    h = host.lower().rstrip(".")
    for s in sans:
        s = s.lower().rstrip(".")
        if s == h:
            return True
        if s.startswith("*.") and h.count(".") == s.count(".") and h.endswith(s[1:]):
            return True
    return False


# ═══════════════════ CT 로그 (crt.sh) ═══════════════════
# 공개 신뢰 인증서는 CT 로그에 등록된다 (브라우저 요구사항).
# 받은 인증서가 CT 에 없으면 사설 CA 발급 또는 TLS 가로채기 재서명의 근거가 된다.

CRTSH = "crt.sh"

# 주요 공개 CA. CT 미등록 경고를 완화하는 데만 쓴다 (목록에 있으면 색인 지연으로 처리).
PUBLIC_CA = (
    "let's encrypt", "digicert", "sectigo", "globalsign", "amazon", "google trust",
    "godaddy", "entrust", "zerossl", "buypass", "certum", "identrust", "isrg",
    "microsoft", "apple public", "comodo", "thawte", "geotrust", "rapidssl",
    "ssl.com", "actalis", "harica", "quovadis", "starfield", "cloudflare",
    "telia", "swisssign", "twca", "e-tugra", "firstserver", "trustasia",
)


def is_public_ca(issuer_dn: str) -> bool:
    """발급자가 주요 공개 CA 인지 여부.

    부분일치 오인('badssl.com' 이 'ssl.com' 에 걸림)을 막기 위해 낱말 경계로 비교한다."""
    low = issuer_dn.lower()
    for name in PUBLIC_CA:
        if re.search(r"(?:^|[^a-z0-9.])" + re.escape(name) + r"(?:$|[^a-z0-9])", low):
            return True
    return False


def issuer_key(issuer: str) -> str:
    """비교용 발급자 키 (CN 우선, 없으면 O)."""
    m = re.search(r"(?:commonName|CN)=([^,]+)", issuer)
    if not m:
        m = re.search(r"(?:organizationName|O)=([^,]+)", issuer)
    return (m.group(1) if m else issuer).strip().lower()


@dataclass
class CtInfo:
    reachable: bool = False
    hist_ok: bool = False          # 이력 조회 응답 수신 여부
    error: str = ""
    serial_found: Optional[bool] = None
    serial_entry: dict = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    issuers: list[str] = field(default_factory=list)


def _crtsh_get(path: str, timeout: float, proxy: Optional[Proxy]) -> tuple[bool, Any]:
    try:
        ans = resolve_system(CRTSH)
        ip = ans.addrs[0] if ans.addrs else ""
        if not ip or is_sinkhole(ip) or is_private(ip):
            # 시스템 DNS 결과가 싱크홀·사설 주소면 DoH 결과로 재시도한다.
            doh = doh_query(CRTSH, "A", timeout, proxy)
            ip = doh.addrs[0] if doh and doh.addrs else ""
        if not ip:
            return False, "crt.sh 이름 해석 실패"
        code, body = https_get(CRTSH, ip, path, timeout,
                               {"Accept": "application/json"}, proxy)
        if code != 200:
            return False, f"crt.sh HTTP {code} 응답"
        st, en = body.find(b"["), body.rfind(b"]")
        if st < 0 or en < 0:
            return False, "응답이 JSON 배열이 아님"
        return True, json.loads(body[st:en + 1])
    except Exception as ex:
        return False, f"{type(ex).__name__}: {ex}"


def ct_lookup(domain: str, serial: str, timeout: float,
              proxy: Optional[Proxy] = None) -> CtInfo:
    info = CtInfo()
    # ① 받은 인증서의 CT 등록 여부. serial 은 대문자 16진수.
    if serial:
        ok, data = _crtsh_get(f"/?serial={serial.upper()}&output=json", timeout, proxy)
        if ok:
            info.reachable = True
            info.serial_found = bool(data)
            if data:
                info.serial_entry = data[0]
        else:
            info.error = str(data)
    # ② 이 이름의 발급 이력 — 평소와 다른 발급자 확인용.
    ok, data = _crtsh_get(f"/?q=%25.{domain}&output=json", timeout * 2, proxy)
    if ok and isinstance(data, list):
        info.reachable = True
        info.hist_ok = True
        info.history = data
        names, issuers = set(), set()
        for e in data:
            for n in (e.get("name_value") or "").split("\n"):
                n = n.strip().lower()
                if n:
                    names.add(n)
            iss = e.get("issuer_name") or ""
            m = re.search(r"CN=([^,]+)", iss)
            issuers.add((m.group(1) if m else iss)[:40])
        info.names = sorted(names)
        info.issuers = sorted(issuers)
    elif not info.error:
        info.error = str(data)
    return info


# ═══════════════════════ HTTP ═══════════════════════
# L6 HTTP — 하위 계층이 정상일 때의 애플리케이션 계층 검사.

@dataclass
class HttpStep:
    code: int
    location: str = ""


@dataclass
class HttpInfo:
    ok: bool = False
    error: str = ""
    code: int = 0
    version: str = ""
    server: str = ""
    size: int = 0
    chain: list[HttpStep] = field(default_factory=list)
    final_url: str = ""
    t_connect: int = 0
    t_tls: int = 0
    t_ttfb: int = 0
    t_total: int = 0
    proxy_hdrs: dict[str, str] = field(default_factory=dict)
    alt_svc: str = ""
    body_head: str = ""
    redirect_error: str = ""
    redirect_sinkhole: bool = False      # 이동 대상 이름이 싱크홀로 해석됨 (DNS 차단)
    timed_out: bool = False              # 첫 요청이 응답 대기 중 타임아웃


PROXY_HDRS = ("via", "x-cache", "cf-ray", "x-amz-cf-id", "x-served-by",
              "x-varnish", "age", "x-forwarded-for", "x-proxy-id")

# 200 응답이라도 본문이 차단·한도 초과 안내일 수 있다.
# 거절 안내 문구. 스크립트·태그를 제거한 본문 텍스트에만 적용한다 (reCAPTCHA 스크립트 등 오탐 방지).
DENY_PAT = re.compile(
    r"LIMITED_NUMBER_OF_SERVICE_REQUESTS|SERVICE_KEY_IS_NOT_REGISTERED|errMsg"
    r"|rate.?limit(?:ed| exceeded)|quota exceed|Access Denied|403 Forbidden|warning\.or\.kr"
    r"|unauthori[sz]ed|Just a moment\.\.\.", re.I)


def visible_text(body: str) -> str:
    """HTML 에서 script·style·태그를 제거한 텍스트 (XML 오류 필드는 태그 이름 유지)."""
    t = re.sub(r"(?is)<(script|style)\b.*?(</\1>|$)", " ", body)
    t = re.sub(r"(?s)<!--.*?-->", " ", t)
    t = re.sub(r"<(/?)(errMsg|returnAuthMsg|returnReasonCode)\b[^>]*>", r" \2 ", t, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    return " ".join(t.split())
ERRFIELD_PAT = re.compile(
    r"<errMsg>([^<]{1,120})</errMsg>|\"errMsg\"\s*:\s*\"([^\"]{1,120})\""
    r"|<returnAuthMsg>([^<]{1,120})</returnAuthMsg>", re.I)


def http_probe(host: str, ip: str, port: int, timeout: float, scheme: str,
               proxy: Optional[Proxy] = None, max_redirects: int = 5,
               path: str = "/") -> HttpInfo:
    info = HttpInfo()
    t0 = time.monotonic()
    ms = lambda: int((time.monotonic() - t0) * 1000)
    cur_host, cur_ip, cur_port, cur_scheme = host, ip, port, scheme

    for hop in range(max_redirects + 1):
        raw = sock = None
        # HTTP 프록시 + 평문 HTTP: CONNECT 대신 절대 URI GET (Squid 기본 설정은 443 외 CONNECT 거부)
        use_get = proxy is not None and proxy.scheme == "http" and cur_scheme == "http"
        try:
            raw = open_stream(cur_ip or cur_host, cur_port, timeout, proxy, tunnel=not use_get)
            if hop == 0:
                info.t_connect = ms()
            sock = raw
            if cur_scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                try:
                    ctx.set_alpn_protocols(["http/1.1"])
                except NotImplementedError:
                    pass
                sock = ctx.wrap_socket(raw, server_hostname=(
                    None if is_ip_literal(cur_host) else cur_host))
                if hop == 0:
                    info.t_tls = ms()
            sock.settimeout(timeout)
            hp = _hostport(cur_host, cur_port, cur_scheme)
            target = f"http://{hp}{path}" if use_get else path
            auth = ""
            if use_get and proxy.user is not None:
                cred = base64.b64encode(f"{proxy.user}:{proxy.password or ''}".encode()).decode()
                auth = f"Proxy-Authorization: Basic {cred}\r\n"
            req = (f"GET {target} HTTP/1.1\r\nHost: {hp}\r\n{auth}"
                   f"User-Agent: netcheck/{VERSION}\r\nAccept: */*\r\n"
                   f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
            sock.sendall(req.encode())
            buf = b""
            first_byte = None
            need = None          # Content-Length 가 있으면 그 길이에서 멈춘다.
            while True:
                chunk = sock.recv(65536)
                if first_byte is None:
                    first_byte = ms()
                if not chunk:
                    break
                buf += chunk
                if need is None and b"\r\n\r\n" in buf:
                    head_b, _, body_b = buf.partition(b"\r\n\r\n")
                    cl = re.search(rb"(?im)^content-length:\s*(\d+)", head_b)
                    if cl:
                        need = len(head_b) + 4 + int(cl.group(1))
                    elif re.search(rb"(?im)^transfer-encoding:\s*chunked", head_b):
                        need = -1        # 종료 청크(0\r\n\r\n) 대기
                if need is not None:
                    # 다 받았으면 서버의 연결 종료를 기다리지 않는다.
                    if need >= 0 and len(buf) >= need:
                        break
                    if need < 0 and chunked_done(buf.partition(b"\r\n\r\n")[2]):
                        break
                if len(buf) > 512 * 1024:
                    break
            if hop == 0:
                info.t_ttfb = first_byte or ms()
            head, _, body = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", "replace").split("\r\n")
            status = lines[0].split(None, 2)
            code = int(status[1]) if len(status) > 1 and status[1].isdigit() else 0
            info.version = status[0].replace("HTTP/", "") if status else ""
            hdrs: dict[str, str] = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()
            loc = hdrs.get("location", "")
            info.chain.append(HttpStep(code, loc))
            info.code = code
            info.server = hdrs.get("server", info.server)
            info.alt_svc = hdrs.get("alt-svc", info.alt_svc)
            for k in PROXY_HDRS:
                if k in hdrs:
                    info.proxy_hdrs[k] = hdrs[k][:40]
            if "chunked" in hdrs.get("transfer-encoding", "").lower():
                body = dechunk(body)
            info.size = len(body)
            info.body_head = body[:2000].decode("utf-8", "replace")
            info.final_url = f"{cur_scheme}://{_hostport(cur_host, cur_port, cur_scheme)}{path}"
            info.ok = True

            if 300 <= code < 400 and loc and hop < max_redirects:
                nh, np_, nsch, npath = _split_url(loc, cur_host, cur_port, cur_scheme, path)
                if (nh, np_, nsch, npath) == (cur_host, cur_port, cur_scheme, path):
                    info.redirect_error = "같은 주소로 반복 이동 — 서버 리다이렉트 설정 오류"
                    break
                if nh != cur_host and proxy is not None and proxy.remote_dns:
                    cur_ip = ""          # 이름 해석은 프록시가 수행
                elif nh != cur_host:
                    try:
                        cur_ip = socket.getaddrinfo(nh, None)[0][4][0]
                    except OSError as ex:
                        info.redirect_error = f"{nh} 이름 해석 실패 ({ex.strerror or ex})"
                        break
                    if is_sinkhole(cur_ip):
                        info.redirect_error = (
                            f"이동 대상 {nh} 이 {cur_ip} 로 해석됨 — 싱크홀 주소")
                        info.redirect_sinkhole = True
                        break
                cur_host, cur_port, cur_scheme, path = nh, np_, nsch, npath
                continue
            if 300 <= code < 400 and loc:
                info.redirect_error = f"리다이렉트 {max_redirects}회 초과"
            break
        except ProxyError as ex:
            info.error = f"프록시 거부: {ex}"
            break
        except Exception as ex:
            if hop == 0:
                info.error = str(ex) or type(ex).__name__
                info.timed_out = isinstance(ex, (socket.timeout, TimeoutError))
            else:
                # 첫 요청은 성공, 리다이렉트 대상에서 실패 — 이동 대상 문제로 기록한다.
                info.redirect_error = f"{cur_host}:{cur_port} 로 이동 중 실패 — {trunc(str(ex), 40)}"
            break
        finally:
            # SSL 소켓과 원본 소켓을 모두 닫는다 (fd 누수 방지).
            for h in (sock, raw):
                if h is not None:
                    try:
                        h.close()
                    except OSError:
                        pass
    info.t_total = ms()
    return info


def _hostport(host: str, port: int, scheme: str) -> str:
    """Host 헤더·URL 용 표기. IPv6 는 대괄호, 기본 포트는 생략."""
    h = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return h if port == default else f"{h}:{port}"


def _split_url(url: str, base_host: str, base_port: int,
               base_scheme: str, base_path: str = "/") -> tuple[str, int, str, str]:
    """Location 값을 현재 URL 기준으로 해석한다 (상대 경로·//host 형식 포함)."""
    base = f"{base_scheme}://{_hostport(base_host, base_port, base_scheme)}{base_path}"
    u = urlsplit(urljoin(base, url))
    sch = (u.scheme or base_scheme).lower()
    try:
        port = u.port
    except ValueError:
        port = None
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return (u.hostname or base_host, port or (443 if sch == "https" else 80), sch, path)


def chunked_done(body: bytes) -> bool:
    """chunked 본문이 종료 청크까지 모두 도착했는지."""
    pos = 0
    while True:
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            return False
        try:
            size = int(body[pos:nl].split(b";")[0].strip(), 16)
        except ValueError:
            return False
        if size == 0:
            return body.find(b"\r\n\r\n", nl) >= 0 or body.endswith(b"\r\n\r\n")
        pos = nl + 2 + size + 2
        if pos > len(body):
            return False


# ═══════════════════════ 경로 ═══════════════════════
# ICMP 원시 소켓은 root 가 필요하므로 시스템 traceroute 를 쓴다.

@dataclass
class Hop:
    n: int
    ips: list[str] = field(default_factory=list)
    rtt: Optional[float] = None
    recv: int = 0
    sent: int = 0
    meta: Optional[IpMeta] = None

    @property
    def ip(self) -> str:
        return self.ips[0] if self.ips else "*"

    @property
    def ecmp(self) -> bool:
        return len(self.ips) > 1


IPRE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]+$")


def parse_traceroute(text: str) -> list[Hop]:
    """traceroute 출력 파싱. ECMP 홉은 홉 번호 없는 줄로 이어지므로 같은 홉으로 묶는다."""
    hops: list[Hop] = []
    cur: Optional[Hop] = None
    for line in text.splitlines():
        toks = line.split()
        if not toks:
            continue
        start = 0
        if toks[0].isdigit() and not IPRE.match(toks[0]):
            cur = Hop(int(toks[0]))
            hops.append(cur)
            start = 1
        if cur is None:
            continue
        i = start
        while i < len(toks):
            t = toks[i]
            if t == "*":
                cur.sent += 1
            elif IPRE.match(t):
                if t not in cur.ips:
                    cur.ips.append(t)
            elif i + 1 < len(toks) and toks[i + 1] == "ms":
                try:
                    # Windows tracert 는 1ms 미만을 '<1' 로 쓴다
                    # Windows tracert 는 1ms 미만을 '<1' 로 쓴다 → 0.5ms 로 기록
                    v = 0.5 if t.startswith("<") else float(t)
                    cur.recv += 1
                    cur.sent += 1
                    cur.rtt = v if cur.rtt is None else min(cur.rtt, v)
                except ValueError:
                    pass
                i += 1
            i += 1
    return hops


def traceroute(ip: str, max_hops: int, probes: int,
               timeout: int) -> tuple[list[Hop], str]:
    if IS_WIN:
        # tracert 는 ICMP 만, 홉당 3회 고정 (-q 없음). 무응답 홉은 약 3초씩 걸린다.
        out = run_cmd(["tracert", "-d", "-h", str(max_hops), "-w", "1000", ip],
                      max(timeout, max_hops * 4 + 20))
        hops = parse_traceroute(out)
        return (hops, "ICMP") if sum(1 for h in hops if h.ips) > 1 else ([], "무응답")
    exe = shutil.which("traceroute") or "/usr/sbin/traceroute"
    for mode, label in (([], "UDP"), (["-I"], "ICMP")):
        cmd = [exe, "-n", *mode, "-w", "1", "-q", str(probes),
               "-m", str(max_hops), ip]
        out = run_cmd(cmd, timeout)
        if not out:
            continue
        hops = parse_traceroute(out)
        if sum(1 for h in hops if h.ips) > 1:
            return hops, label
    return [], "무응답"


def ping_size(ip: str, payload: int) -> bool:
    """DF 설정 후 payload 바이트로 ping. 통과하면 True.

    경로 MTU = payload + 28 (IP 20 + ICMP 8).
    종료 코드가 OS 마다 다르므로 응답 줄 유무로 판단한다."""
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "1500", "-f", "-l", str(payload), ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", "1500", "-D", "-s", str(payload), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "2", "-M", "do", "-s", str(payload), ip]
    out = run_cmd(cmd, 8)
    return bool(re.search(r"TTL[=:]", out, re.I) or re.search(r"\bttl=\d+", out, re.I))


def ping(target: str, count: int = 5) -> tuple[Optional[float], Optional[float], Optional[int]]:
    """(손실률%, 평균 RTT, 응답 TTL). TTL 로 역방향 홉 수를 추정한다.

    Windows ping 요약 줄은 번역되므로 응답 줄의 'TTL=' 과 '<숫자>ms' 토큰만 센다."""
    if IS_WIN:
        cmd = ["ping", "-n", str(count), "-w", "1000", target]
    elif IS_MAC:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", "800", "-t", "6", target]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", "1", "-w", "6", target]
    out = run_cmd(cmd, 20)
    if not out.strip():
        return None, None, None

    ttl_m = re.search(r"TTL[=:\s]*(\d+)", out, re.I)
    ttl = int(ttl_m.group(1)) if ttl_m else None

    if IS_WIN:
        # 'TTL=' 이 있는 줄이 응답 줄.
        # IPv6 응답 줄에는 TTL= 이 없으므로 대상 주소 + '<숫자>ms' 토큰으로도 판별
        replies = [ln for ln in out.splitlines()
                   if re.search(r"TTL[=:]", ln, re.I)
                   or (target in ln and re.search(r"[=<]\s*\d+\s*ms", ln, re.I))]
        times = []
        for ln in replies:
            m = re.search(r"[=<]\s*(\d+)\s*ms", ln, re.I)
            if m:
                times.append(float(m.group(1)))
        recv = len(replies)
        loss = (count - recv) * 100.0 / count if count else None
        avg = (sum(times) / len(times)) if times else None
        return (loss, avg, ttl)

    loss = re.search(r"([\d.]+)%\s*packet loss", out)
    avg = re.search(r"=\s*[\d.]+/([\d.]+)/", out)
    return (float(loss.group(1)) if loss else None,
            float(avg.group(1)) if avg else None, ttl)


# ═══════════════════════ 진단 본체 ═══════════════════════

@dataclass
class Target:
    host: str
    port: int
    key: str = ""               # 결과 구분 키. 같은 호스트가 여러 번이면 host:port
    ips: list[str] = field(default_factory=list)
    ips6: list[str] = field(default_factory=list)
    truth: list[str] = field(default_factory=list)
    v6_ok: Optional[bool] = None
    ttl_dist: Optional[int] = None
    mss: Optional[int] = None
    rpki: str = ""
    path: str = "/"
    tcp_ok: bool = False
    dns_suspect: bool = False   # DNS 응답이 싱크홀·사설·조작으로 판정됨
    os_override: bool = False   # OS 해석기 결과가 직접 질의와 다름 (hosts·분할 DNS)
    conn_ip: str = ""           # TCP 연결에 성공한 첫 IP (L4 이후 검사에 사용)
    scheme: str = ""            # URL 로 지정한 경우 http | https

    @property
    def ip(self) -> str:
        """이후 계층 검사 대상 IP: 연결된 IP, 없으면 첫 해석 IP."""
        return self.conn_ip or (self.ips[0] if self.ips else "")
    meta: Optional[IpMeta] = None


class Netcheck:
    def __init__(self, args: argparse.Namespace):
        self.a = args
        self.st = Style(args.color, getattr(args, "unicode_ok", True))
        self.rep = Report()
        self.proxy: Optional[Proxy] = args.proxy_obj
        self.pool = futures.ThreadPoolExecutor(max_workers=16)
        self.internal_errors = 0
        self.errors_by: dict[str, int] = {}     # 대상 키 → 예외로 중단된 계층 수 ("" 는 공통)
        # 구조화 이벤트 수신자 (GUI 용, 선택)
        self.sink: Optional[Callable[[str, dict], None]] = None
        # 중단 확인 콜백. 오래 걸리는 구간에서 주기적으로 호출한다.
        self.abort_check: Optional[Callable[[], None]] = None
        self.layer = ""

    # ── 출력 헬퍼 ──
    def emit(self, kind: str, **data) -> None:
        if self.sink:
            try:
                self.sink(kind, data)
            except Exception:
                pass          # 수신자 오류는 진단에 영향을 주지 않는다
            # BaseException(중단 신호)은 전파한다

    def _mark_name(self, mark: str) -> str:
        # 기호 → 상태 이름 (GUI 표시용)
        for name, glyph in (("ok", self.st.OK), ("ng", self.st.NG),
                            ("wn", self.st.WN), ("info", self.st.IN)):
            if mark == glyph:
                return name
        return "blame" if "→" in mark else "bar"

    def sect(self, title: str) -> None:
        self.layer = title.split(" ", 1)[0] if title[:1] == "L" else "판정"
        self.emit("section", layer=self.layer, title=title)
        if not self.a.json:
            print(f"\n{self.st.B}{title}{self.st.RST}")

    def row(self, mark: str, label: str, text: str = "") -> None:
        self.emit("row", layer=self.layer, mark=self._mark_name(mark),
                  label=label, text=text)
        if not self.a.json:
            print(f"  {mark} {pad(label, 16)} {text}")

    def note(self, text: str) -> None:
        self.emit("note", layer=self.layer, text=text)
        if not self.a.json:
            print(f"      {self.st.DIM}{text}{self.st.RST}")

    def mark(self, ok: bool, warn: bool = False) -> str:
        return self.st.WN if warn else (self.st.OK if ok else self.st.NG)

    def ck(self) -> None:
        if self.abort_check:
            self.abort_check()

    def safe(self, layer: str, fn: Callable, *args, default: Any = None) -> Any:
        """계층 검사 중 예외가 나도 나머지 계층은 계속 검사한다."""
        try:
            return fn(*args)
        except KeyboardInterrupt:
            raise
        except Exception as ex:
            self.internal_errors += 1
            self.errors_by[self.rep.cur] = self.errors_by.get(self.rep.cur, 0) + 1
            self.row(self.st.WN, "내부 오류",
                     f"{layer} 검사 중 예외 — {type(ex).__name__}: {trunc(str(ex), 50)}")
            self.rep.add(WARN, layer,
                         f"{layer} 검사가 예외로 중단됨({type(ex).__name__}). "
                         "이 계층 결과는 불완전함.")
            return default

    # ══════════ L0 · 로컬 환경 ══════════
    def l0_local(self) -> None:
        self.sect("L0 · 로컬 환경 — 경로·주소·프록시")
        gw, iface = default_route()
        self.rep.data["gateway"], self.rep.data["interface"] = gw, iface
        if not gw:
            self.row(self.st.NG, "기본 경로", "없음 — 외부로 나가는 경로 없음")
            self.rep.add(CRIT, "L0", "기본 게이트웨이 없음. Wi-Fi·LAN 연결 확인 필요.")
            return
        addr, mtu = iface_info(iface)
        self.rep.data.update(address=addr, mtu=mtu)
        self.row(self.st.OK, "기본 경로",
                 f"{gw}  ({iface}, 로컬 주소 {addr or '?'}, MTU {mtu or '?'})")
        if addr and addr.startswith("169.254."):
            self.row(self.st.NG, "주소 획득", "링크로컬 — DHCP 실패")
            self.rep.add(CRIT, "L0", "169.254 링크로컬 주소. DHCP 로 IP 를 받지 못함.")
        if mtu and mtu not in (1500, 9000, 1492):
            self.row(self.st.WN, "MTU", f"{mtu} — 비표준 값. 큰 패킷 손실 가능")

        # 외부에서 보이는 공인 IP (IP 차단 여부 확인 기준)
        pub = self.public_ip()
        if pub:
            self.rep.data["public_ip"] = pub
            same = (pub == addr)
            self.row(self.st.IN, "공인 IP",
                     f"{pub}  ({'NAT 없음' if same else 'NAT 사용. 외부에는 이 주소로 보임'})")
            if "CGNAT" in ip_class(pub):
                self.row(self.st.WN, "CGNAT", "여러 가입자가 공인 주소를 공유")
                self.rep.add(INFO, "L0",
                             "공인 IP 가 CGNAT 대역. 같은 주소를 쓰는 다른 가입자 때문에 차단될 수 있음.")
        else:
            self.row(self.st.IN, "공인 IP", "확인 불가 (외부 조회 실패)")

        tuns = tunnels()
        if iface in tuns:
            self.row(self.st.WN, "VPN", f"기본 경로가 터널({iface}) — 이후 검사는 모두 VPN 경유")
            self.rep.add(WARN, "L0", f"기본 경로가 VPN({iface}). VPN 을 끄고 재검사하면 구간 비교 가능.")
        elif tuns:
            self.row(self.st.IN, "터널", f"{' '.join(tuns)} (기본 경로는 아님)")

        if self.a.ipv == 6 and not self.proxy and not local_ip_for("2001:4860:4860::8888"):
            self.row(self.st.NG, "IPv6", "로컬 IPv6 경로 없음 — -6 검사 불가")
            self.rep.add(CRIT, "L0",
                         "로컬 기기에 IPv6 경로 없음 — -6(IPv6 강제) 검사 불가.", "no_local_v6")

        sys_px = system_proxy()
        env_px = [k for k in ("http_proxy", "https_proxy", "all_proxy",
                              "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") if os.environ.get(k)]
        if self.proxy:
            r = tcp_probe(self.proxy.host, self.proxy.port, self.a.timeout)
            if r.ok:
                self.row(self.st.IN, "프록시", f"{self.proxy.label} 경유 검사 (지정됨, 연결 {r.ms}ms)")
            else:
                self.row(self.st.NG, "프록시", f"{self.proxy.label} 연결 불가 — {WHY[r.status]}")
                self.rep.add(CRIT, "L0",
                             f"지정한 프록시({self.proxy.label})에 연결할 수 없음 ({WHY[r.status]}). "
                             "프록시 주소·포트·실행 상태 확인 — 이후 결과는 모두 이 영향.", "proxy_down")
        elif sys_px or env_px:
            src = ", ".join(filter(None, [sys_px, " ".join(env_px)]))
            self.row(self.st.WN, "프록시", f"시스템 설정: {src}")
            self.note("--proxy 미지정 시 직접 연결로 검사 — 프록시를 쓰는 앱과 결과가 다를 수 있음")
            self.rep.add(WARN, "L0",
                         f"시스템 프록시 설정됨({src}). 앱과 같은 경로로 검사하려면 "
                         "--proxy 지정 필요.")
        else:
            self.row(self.st.OK, "프록시", "없음")

    def public_ip(self) -> str:
        try:
            _c, body = https_get("one.one.one.one", "1.1.1.1", "/cdn-cgi/trace",
                                 min(self.a.timeout, 5), None, self.proxy)
            m = re.search(r"^ip=(\S+)", body.decode("utf-8", "replace"), re.M)
            return m.group(1) if m else ""
        except Exception:
            return ""

    # ══════════ L1 · 게이트웨이 ══════════
    def l1_link(self) -> None:
        gw = self.rep.data.get("gateway")
        if not gw:
            return
        self.sect("L1 · 게이트웨이 — 로컬 네트워크")
        loss, avg, _ttl = ping(gw, 5)
        if loss is None or loss >= 100:
            # 전부 무응답: 공유기의 ICMP 차단과 구분할 수 없으므로 경고로 기록하지 않음
            self.row(self.st.IN, "게이트웨이", f"{gw}  ping 응답 없음 (ICMP 를 차단하는 공유기일 수 있음)")
        elif loss > 0:
            self.row(self.st.WN, "게이트웨이",
                     f"{gw}  손실 {loss:g}%  {avg or ''}ms  — 무선 간섭·케이블 점검")
            self.rep.add(WARN, "L1", f"게이트웨이까지 {loss:g}% 손실. 유선 연결로 재검사 권장.")
        else:
            self.row(self.st.OK, "게이트웨이", f"{gw}  손실 0%  {avg}ms")

    # ══════════ L2 · 인터넷 연결 ══════════
    def l2_internet(self) -> None:
        self.sect("L2 · 인터넷 연결 — DNS 없이 IP 로")
        probes = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"]
        res = list(self.pool.map(
            lambda ip: (ip, tcp_probe(ip, 443, self.a.timeout, self.proxy)), probes))
        up = denied = 0
        for ip, r in res:
            if r.ok:
                up += 1
                self.row(self.st.OK, f"{ip}:443", f"{r.ms} ms")
            elif r.status == PROXY_DENY:
                denied += 1
                self.row(self.st.WN, f"{ip}:443", f"프록시가 IP 주소 연결 거부 {r.detail}".rstrip())
            else:
                self.row(self.st.NG, f"{ip}:443", f"{WHY[r.status]} {r.detail}")
        self.rep.data["internet"] = {"up": up, "tried": len(probes) - denied}
        if denied == len(probes):
            # 많은 사내 프록시가 IP 주소로의 CONNECT 를 정책상 거부함
            self.rep.add(WARN, "L2",
                         "프록시가 IP 주소 목적지 연결을 거부 — 프록시 경유 인터넷 연결 검사 불가 (프록시 정책).")
        elif up == 0 and self.proxy:
            self.rep.add(CRIT, "L2",
                         "프록시 경유로 공용 IP 4곳 모두 연결 실패. 프록시 또는 프록시 이후 회선 문제.")
            self.note("이후 계층의 실패도 같은 원인 — 프록시 먼저 점검")
        elif up == 0:
            self.rep.add(CRIT, "L2",
                         "공용 IP 4곳 모두 연결 실패. 목적지가 아닌 로컬 회선 문제.")
            self.note("이후 계층의 실패도 같은 원인 — 회선 먼저 점검")

    # ══════════ L2c · 프록시 대조 ══════════
    # 직접 연결과 프록시 연결을 각각 측정해 차단 위치를 구분한다.
    def l2c_proxy(self, t: Target) -> None:
        if not self.proxy or not t.ips:
            return
        ip = t.ips[0]
        sink = is_sinkhole(ip)

        # 싱크홀 주소면 직접 연결은 측정 의미가 없다 (0.0.0.0 은 로컬로 연결됨).
        if sink and not self.proxy.remote_dns:
            return
        self.sect("L2c · 프록시 대조 — 직접 연결 vs 프록시")
        if sink:
            # 프록시에 이름 해석을 맡겼을 때 접속되는지 확인한다.
            viapx = tcp_probe(t.host, t.port, self.a.timeout, self.proxy)
            self.row(self.st.NG, "직접", f"{ip} — 싱크홀 주소라 직접 연결 측정 생략")
            self.row(self.mark(viapx.ok), "프록시(이름 전달)",
                     f"{self.proxy.label}  {WHY[viapx.status]} {viapx.detail}".rstrip())
            if viapx.ok:
                self.rep.add(CRIT, "L3",
                             "로컬 DNS 는 싱크홀 주소를 반환하지만 프록시 이름 해석으로는 접속됨 — "
                             "DNS 차단 확인. 프록시로 우회 가능.")
            else:
                self.rep.add(INFO, "L2c",
                             f"프록시 이름 해석으로도 실패({viapx.detail or WHY[viapx.status]}). "
                             "프록시도 같은 DNS 를 쓰거나 목적지가 차단된 상태.")
            return

        direct = tcp_probe(ip, t.port, self.a.timeout, None)
        viapx = tcp_probe(t.host if self.proxy.remote_dns else ip,
                          t.port, self.a.timeout, self.proxy)
        self.row(self.mark(direct.ok), "직접",
                 f"{ip}:{t.port}  {WHY[direct.status]} {direct.detail}".rstrip())
        self.row(self.mark(viapx.ok), "프록시",
                 f"{self.proxy.label}  {WHY[viapx.status]} {viapx.detail}".rstrip())
        if viapx.status == PROXY_DENY:
            self.rep.add(CRIT, "L2c",
                         f"프록시가 목적지 거부({viapx.detail}). 프록시 정책 문제.")
            self.note("거부 사유 기준으로 프록시 정책·인증·허용목록 확인")
        elif viapx.ok and not direct.ok:
            self.rep.add(CRIT, "L2c",
                         "직접 연결 실패, 프록시 연결 성공 — 직접 나가는 트래픽 차단. "
                         "이 네트워크에서는 프록시 경유 필요.")
        elif direct.ok and not viapx.ok:
            self.rep.add(CRIT, "L2c",
                         "직접 연결 성공, 프록시 연결 실패 — 프록시 측 문제. 목적지는 정상.")
        elif viapx.ok and direct.ok:
            self.row(self.st.OK, "판정", "양쪽 모두 연결됨 — 프록시는 원인 아님")

    # ══════════ L2b · 회선 대조 ══════════
    # 회선별로 측정해 통신사 경로 문제와 목적지 장애를 구분한다.
    def l2b_multipath(self, t: Target) -> None:
        if not t.ips or is_sinkhole(t.ips[0]):
            return
        lines = usable_interfaces()
        if len(lines) < 2:
            return
        self.sect("L2b · 회선 대조 — 회선별 연결")
        ip = t.ips[0]
        ok_n = ng_n = 0
        for ifc, sip in lines:
            # Linux 는 출발지 바인딩과 무관하게 목적지 기준으로 경로를 고른다.
            # 실제 나가는 인터페이스가 다르면 측정에서 제외한다 (macOS 는 scoped routing).
            if not IS_MAC and not IS_WIN:
                dev = route_dev(ip, sip)
                if dev and dev != ifc:
                    self.row(self.st.WN, ifc,
                             f"실제 출력 인터페이스가 {dev} — 회선별 측정 불가")
                    continue
            r = tcp_probe(ip, t.port, self.a.timeout, self.proxy, sip)
            if r.ok:
                ok_n += 1
                self.row(self.st.OK, ifc, f"{sip} → {ip}:{t.port}  열림  {r.ms}ms")
            else:
                ng_n += 1
                self.row(self.st.NG, ifc, f"{sip} → {ip}:{t.port}  {WHY[r.status]}")
        if ok_n and ng_n:
            self.rep.add(CRIT, "L2b",
                         "회선별 결과가 다름 — 실패한 회선의 경로 문제. 목적지는 정상.")
            self.note("목적지 장애라면 모든 회선에서 실패함")
        elif ng_n and not ok_n:
            self.rep.add(INFO, "L2b",
                         f"회선 {ng_n}개 모두 실패 — 특정 회선 문제가 아닌 목적지 또는 공통 경로 문제.")
        elif ok_n > 1:
            self.row(self.st.OK, "판정", f"회선 {ok_n}개 모두 연결됨 — 현재 정상")

    # ══════════ L3 · DNS ══════════
    def l3_dns(self, t: Target) -> bool:
        self.sect("L3 · DNS — 이름 해석")
        if is_ip_literal(t.host):
            t.ips = [t.host]
            self.row(self.st.IN, "생략", f"{t.host} — IP 주소, 이름 해석 불필요")
            return True

        want6 = (self.a.ipv == 6)
        qt = "AAAA" if want6 else "A"
        f_sys = self.pool.submit(resolve_system, t.host, want6)
        f_p1 = self.pool.submit(dns_query, t.host, qt, "1.1.1.1", 2.0)
        f_p2 = self.pool.submit(dns_query, t.host, qt, "8.8.8.8", 2.0)
        f_doh = self.pool.submit(doh_query, t.host, qt, self.a.timeout, self.proxy)
        f_v6 = (self.pool.submit(resolve_system, t.host, True)
                if self.a.ipv != 4 and not want6 else None)
        f_os = self.pool.submit(os_resolve, t.host, want6)

        sys_a, p1, p2 = f_sys.result(), f_p1.result(), f_p2.result()
        truth = f_doh.result()
        v6 = f_v6.result() if f_v6 else None
        try:
            os_addrs = f_os.result(timeout=self.a.timeout + 2)
        except futures.TimeoutError:
            os_addrs = []

        if sys_a.addrs:
            self.row(self.st.OK, "시스템",
                     f"{' '.join(sys_a.addrs)}  ({sys_a.ms}ms, 서버 "
                     f"{' '.join(system_resolvers()) or 'OS 해석기'})")
        else:
            hint = {"NXDOMAIN": "존재하지 않는 이름으로 응답",
                    "SERVFAIL": "DNS 서버 응답 생성 실패 (DNSSEC 실패·상위 서버 장애)",
                    "REFUSED": "DNS 서버가 질의 거부",
                    "TIMEOUT": "DNS 서버 응답 없음"}.get(sys_a.rcode, "주소 레코드 없음")
            self.row(self.st.NG, "시스템", f"{sys_a.rcode} — {hint}  ({sys_a.ms}ms)")
        self.row(self.st.IN if p1.addrs else self.st.WN, "@1.1.1.1",
                 " ".join(p1.addrs) or f"답 없음 ({p1.rcode})")
        self.row(self.st.IN if p2.addrs else self.st.WN, "@8.8.8.8",
                 " ".join(p2.addrs) or f"답 없음 ({p2.rcode})")
        if truth and truth.addrs:
            self.row(self.st.IN, "DoH(대조)", " ".join(truth.addrs))
        elif truth:
            self.row(self.st.IN if truth.rcode == "NXDOMAIN" else self.st.WN, "DoH(대조)",
                     f"{truth.rcode} — " + ("DoH 에서도 존재하지 않는 이름"
                                            if truth.rcode == "NXDOMAIN" else "주소 레코드 없음"))
        else:
            self.row(self.st.WN, "DoH(대조)", "확인 불가 — DoH 차단 또는 인터넷 연결 없음")
        if os_addrs and set(os_addrs) != set(sys_a.addrs):
            # 앱이 실제로 쓰는 값. hosts 파일·도메인별 DNS 설정이 반영됨
            self.row(self.st.IN, "OS 해석기",
                     f"{' '.join(os_addrs)} — hosts 파일·도메인별 DNS 적용 (앱이 사용하는 값)")
        if sys_a.cnames:
            self.row(self.st.IN, "CNAME", " ".join(sys_a.cnames))
            if FILTER_CNAME.search(" ".join(sys_a.cnames)):
                self.row(self.st.WN, "필터 CNAME", "정책용 CNAME 으로 연결됨")
                self.rep.add(WARN, "L3",
                             f"{t.host} 가 {' '.join(sys_a.cnames)} 로 CNAME 됨. 네트워크 필터링 정책.")
        # @1.1.1.1(평문 53) 응답에 필터 CNAME 이 있고 같은 서버의 DoH 응답에는 없으면 53번 가로채기
        if (truth is not None and FILTER_CNAME.search(" ".join(p1.cnames))
                and not FILTER_CNAME.search(" ".join(truth.cnames))):
            self.row(self.st.WN, "53번 가로채기", "@1.1.1.1 평문 질의에 필터 CNAME, DoH 응답에는 없음")
            self.rep.add(WARN, "L3",
                         "평문 DNS(53) 가로채기 — 공용 DNS 로 질의해도 네트워크 필터 응답. "
                         "DNS 서버 변경으로 우회 불가 (DoH/DoT 필요).", "dns53_intercept")
        if v6 and v6.addrs:
            sink6 = is_sinkhole(v6.addrs[0])
            self.row(self.st.WN if sink6 else self.st.IN, "AAAA",
                     " ".join(v6.addrs) + (" — IPv6 도 싱크홀" if sink6 else ""))
        if sys_a.authentic:
            self.row(self.st.IN, "DNSSEC", "검증됨 (AD 플래그)")
        elif sys_a.rcode == "SERVFAIL" and p1.rcode == "SERVFAIL":
            self.row(self.st.WN, "DNSSEC", "공용 해석기도 SERVFAIL — DNSSEC 서명 오류 의심")
        if sys_a.ttl is not None and sys_a.ttl <= 60:
            self.row(self.st.IN, "TTL", f"{sys_a.ttl}초 — 짧은 TTL (GSLB·장애 조치용, 응답 IP 가 자주 바뀜)")

        t.truth = truth.addrs if truth else []
        t.ips6 = [x for x in (v6.addrs if v6 else []) if not is_sinkhole(x)]

        addrs = os_addrs or sys_a.addrs        # 앱과 같은 값 우선
        t.os_override = bool(os_addrs and set(os_addrs) != set(sys_a.addrs))
        if want6 and not addrs:
            self.row(self.st.NG, "IPv6", "AAAA 레코드 없음 — -6 옵션으로 진단 불가")
            self.rep.add(CRIT, "L3", f"{t.host} AAAA 레코드 없음.")
            return False
        if not addrs and t.ips6:
            # A 레코드 없음, AAAA 만 있음
            self.row(self.st.IN, "IPv4", "주소 없음 — IPv6 전용 이름")
            if self.proxy or local_ip_for(t.ips6[0]):
                addrs = t.ips6
            else:
                self.rep.add(CRIT, "L4", f"{t.host} 는 IPv6 전용 이름 — 로컬 기기에 IPv6 경로 없음.",
                             "no_local_v6")
                t.ips = []
                return False
        return self._judge_dns(t, addrs, sys_a, p1, p2, truth)

    def _judge_dns(self, t: Target, addrs: list[str], sys_a: DnsAnswer,
                   p1: DnsAnswer, p2: DnsAnswer, truth: Optional[DnsAnswer]) -> bool:
        """해석 결과 판정: 싱크홀·조작·존재하지 않는 이름 구분."""
        if addrs and is_sinkhole(addrs[0]):
            t.dns_suspect = True
            self.row(self.st.NG, "판정", f"싱크홀 — {addrs[0]} 로 응답 (DNS 차단)")
            src = ("hosts 파일·로컬 해석 설정" if t.os_override
                   else "공유기·보안 SW·사내 DNS 정책")
            self.rep.add(CRIT, "L3", f"{t.host} → {addrs[0]} (싱크홀). {src}에 의한 차단.",
                         "hosts_block" if t.os_override else "")
        elif addrs and is_private(addrs[0]):
            t.dns_suspect = True
            self.row(self.st.WN, "판정", f"사설 IP({addrs[0]}) 로 응답 — 내부 DNS 또는 가로채기")
            self.rep.add(WARN, "L3", f"{t.host} 가 사설 IP 로 해석됨. 사내망·공유기 DNS 사용 중.")

        # CDN·GSLB 는 질의 위치마다 다른 IP 를 주므로 IP 가 아니라 소유 AS 로 비교한다.
        hijack = False
        if t.truth and addrs and not (set(addrs) & set(t.truth)):
            metas = cymru_bulk([addrs[0], t.truth[0]])
            a1 = metas.get(addrs[0], IpMeta(addrs[0])).asn
            a2 = metas.get(t.truth[0], IpMeta(t.truth[0])).asn
            if metas.ok and a1 == a2 and a1 not in ("-", "NA"):
                self.row(self.st.IN, "응답 차이",
                         f"시스템과 DoH 의 IP 다름 — 같은 AS({a1}), CDN/GSLB")
            elif self._cert_ok(t, addrs[0]):
                # 다른 AS(ISP 내 캐시·다중 AS 기업) 라도 인증서가 그 이름으로 검증되면 정상
                self.row(self.st.IN, "응답 차이",
                         f"시스템과 DoH 의 IP 다름 — 시스템 IP 의 인증서가 {t.host} 로 검증됨 "
                         "(ISP 내 캐시·다중 AS CDN)")
            elif not metas.ok:
                self.row(self.st.WN, "응답 차이", "시스템과 DoH 의 IP 다름 — 소유 AS 조회 실패로 판정 보류")
                self.rep.add(WARN, "L3",
                             f"{t.host} 시스템 DNS 와 DoH 응답 IP 다름. whois 조회 실패로 조작 여부 판정 불가.")
            else:
                hijack = True
                t.dns_suspect = True
                self.row(self.st.NG, "가로채기",
                         f"시스템 응답과 DoH 응답의 소유 AS 다름 (AS{a1} vs AS{a2})")
                self.note(f"시스템={' '.join(addrs)}")
                self.note(f"DoH   ={' '.join(t.truth)}")
                self.rep.add(CRIT, "L3",
                             f"DNS 응답 조작. 시스템 {' '.join(addrs)}(AS{a1}), "
                             f"DoH {' '.join(t.truth)}(AS{a2}).")
        if hijack and p1.addrs and set(p1.addrs) == set(addrs):
            self.row(self.st.NG, "투명 가로채기",
                     "@1.1.1.1 질의도 같은 응답 — 53번 포트 가로채기")
            self.rep.add(CRIT, "L3",
                         "평문 DNS(53) 가 투명 프록시로 가로채짐. DNS 서버 변경으로는 해결 안 됨 — DoH/DoT 필요.")

        if addrs:
            t.ips = addrs
            return True

        # 존재하지 않는 이름과 차단된 이름을 구분한다.
        public = (truth.addrs if truth else []) or p1.addrs or p2.addrs
        if sys_a.rcode == "NXDOMAIN" and not public and truth is None:
            self.row(self.st.NG, "결론", "존재하지 않는 이름 — 공용 DNS NXDOMAIN (DoH 확인 불가)")
            self.rep.add(CRIT, "L3b",
                         f"{t.host} 이름 없음 (공용 DNS 기준, DoH 확인 불가). 오타·미등록·만료 확인 필요.")
        elif sys_a.rcode == "NXDOMAIN" and truth is None and public:
            self.row(self.st.NG, "결론", "시스템 DNS 만 NXDOMAIN — 공용 DNS 는 주소 응답 (NXDOMAIN 주입)")
            self.rep.add(CRIT, "L3",
                         f"{t.host} 를 시스템 DNS 만 NXDOMAIN 으로 응답. 공용 DNS 결과는 "
                         f"{' '.join(public[:3])} — DNS 차단.")
        elif sys_a.rcode == "SERVFAIL" and public:
            self.row(self.st.NG, "결론", "시스템 DNS 만 SERVFAIL — 공용 DNS·DoH 는 정상 응답")
            self.rep.add(CRIT, "L3",
                         f"{t.host} 시스템 DNS 서버만 SERVFAIL. 공용 DNS 는 {' '.join(public[:3])} 응답 — "
                         "로컬 DNS 서버 장애 또는 필터.")
        elif sys_a.rcode == "NXDOMAIN" and (not truth or truth.rcode == "NXDOMAIN"):
            self.row(self.st.NG, "결론", "존재하지 않는 이름 — 공용 DNS·DoH 모두 NXDOMAIN")
            self.rep.add(CRIT, "L3b",
                         f"{t.host} 이름 없음. 오타·미등록·만료 확인 필요.")
        elif sys_a.rcode == "NXDOMAIN" and truth and truth.addrs:
            self.row(self.st.NG, "결론", "시스템 DNS 만 NXDOMAIN — NXDOMAIN 주입 차단")
            self.rep.add(CRIT, "L3",
                         f"{t.host} 를 시스템 DNS 만 NXDOMAIN 으로 응답. DoH 결과는 "
                         f"{' '.join(truth.addrs)} — DNS 차단.")
        elif sys_a.rcode == "SERVFAIL":
            self.row(self.st.NG, "결론", "SERVFAIL — 권위 서버 장애 또는 DNSSEC 검증 실패")
            self.rep.add(CRIT, "L3b", f"{t.host} SERVFAIL. 도메인 측 DNS 장애 또는 DNSSEC 문제.")
        elif (sys_a.rcode == "NOERROR" and truth is not None
              and truth.rcode == "NOERROR" and not truth.addrs):
            self.row(self.st.NG, "결론", "주소 레코드 없음 — 시스템 DNS·DoH 모두 NODATA")
            self.rep.add(CRIT, "L3b",
                         f"{t.host} 주소 레코드 없음(NODATA). 시스템 DNS·DoH 응답 동일 — "
                         "도메인의 DNS 레코드 설정 확인 필요.")
        else:
            self.row(self.st.NG, "결론", "이름 해석 실패 — 이후 단계 진행 불가")
            self.rep.add(CRIT, "L3", f"{t.host} 이름 해석 실패({sys_a.rcode}).")
        t.ips = []
        return False

    # ══════════ L3b · 도메인 상태 ══════════
    def l3b_domain(self, t: Target) -> None:
        if is_ip_literal(t.host) or self.a.mode == "quick":
            return
        self.sect("L3b · 도메인 상태 — 등록 정보·권위 서버")
        dom = registrable(t.host)
        txt = whois_domain(dom)
        exp = pick(txt, r"(?:Registry Expiry Date|Expiration Date|expires|paid-till)\s*:\s*(.+)")
        reg = pick(txt, r"Registrar\s*:\s*(.+)")
        status = sorted(set(re.findall(r"(?:Domain Status|status)\s*:\s*(\S+)", txt, re.I)))
        if reg:
            self.row(self.st.IN, "등록기관", reg)
        if exp:
            self.row(self.st.IN, "만료일", exp)
            d = re.search(r"(\d{4})[-.\s]*(\d{2})[-.\s]*(\d{2})", exp)
            if d and f"{d.group(1)}{d.group(2)}{d.group(3)}" < time.strftime("%Y%m%d"):
                self.row(self.st.NG, "만료", "만료일 경과 — 이름 해석 실패 원인")
                self.rep.add(CRIT, "L3b", f"{dom} 도메인 만료 ({exp}).")
        if status:
            bad = [x for x in status
                   if re.search(r"hold|pendingDelete|redemption|suspend", x, re.I)]
            self.row(self.st.NG if bad else self.st.IN, "등록 상태", trunc(" ".join(status), 70))
            if bad:
                self.rep.add(CRIT, "L3b",
                             f"{dom} 정지·삭제 대기 상태({' '.join(bad)}). 등록기관에서 중지됨.")

        # 권위 서버에 직접 질의해 캐시 응답과 비교한다.
        ns = dns_query(dom, "NS", (system_resolvers() or ["1.1.1.1"])[0]).names
        if not ns:
            ns = dns_query(dom, "NS", "1.1.1.1").names
        if not ns:
            self.row(self.st.WN, "권위 서버", "NS 레코드 없음 — 위임 오류 가능")
            return
        self.row(self.st.IN, "권위 서버", " ".join(ns[:3]))
        try:
            nsip = socket.getaddrinfo(ns[0], None, socket.AF_INET)[0][4][0]
        except OSError:
            return
        auth = dns_query(t.host, "AAAA" if self.a.ipv == 6 else "A", nsip)
        if not auth.addrs:
            self.row(self.st.WN, "권위 답 대조", f"권위 서버 응답 없음 ({auth.rcode})")
            return
        if set(auth.addrs) & set(t.ips):
            self.row(self.st.OK, "권위 답 대조", f"캐시와 일치 ({' '.join(auth.addrs)})")
        else:
            self.row(self.st.WN, "권위 답 대조",
                     f"권위={' '.join(auth.addrs)}  캐시={' '.join(t.ips)} — 불일치")
            self.rep.add(WARN, "L3", "권위 서버 응답과 캐시 응답 불일치. 캐시 만료 전이거나 응답 조작.")

    # ══════════ L4 · TCP ══════════
    def l4_tcp(self, t: Target) -> bool:
        self.sect(f"L4 · TCP {t.port} — 3-way handshake  ({self.a.repeat}회)")

        # 싱크홀 주소는 로컬로 연결되므로 측정에서 제외한다.
        real = []
        for ip in t.ips:
            if is_sinkhole(ip):
                self.row(self.st.NG, ip, "싱크홀 주소 — 측정 제외 (로컬로 연결됨)")
            else:
                real.append(ip)
        if not real:
            self.note("싱크홀 주소로 해석됨 — 원인은 L3 (DNS)")
            self.probe_truth(t)
            return False

        # 인터넷에서 라우팅되지 않는 주소 확인 (원인: 경로가 아니라 주소).
        metas = cymru_bulk(real)
        for ip in real:
            cls = ip_class(ip)
            if any(cls.startswith(k) for k in NOT_ROUTABLE):
                self.row(self.st.NG, ip, f"{cls} 대역 — 인터넷 라우팅 불가 주소")
                self.rep.add(CRIT, "L4",
                             f"{ip} 는 {cls} 대역. 설정 또는 DNS 응답 오류.", "bad_addr")
            elif (metas.ok and not is_private(ip)
                  and not metas.get(ip, IpMeta(ip)).routed):
                self.row(self.st.NG, ip, "BGP 미광고 — 전역 라우팅 테이블에 없는 주소")
                self.rep.add(CRIT, "L4",
                             f"{ip} BGP 미광고. 차단이 아니라 도달 경로 자체가 없음.", "bad_addr")

        any_ok = False
        fails: list[tuple[str, str]] = []      # (메시지, 코드) — 다른 IP 성공 여부에 따라 등급 결정
        # 이름 해석을 프록시가 하는 경우(http·socks5h) 프록시에는 호스트명으로 연결 요청 — 1회만
        by_name = self._by_name(t)
        for ip in (real[:1] if by_name else real):
            self.ck()
            s = tcp_series(t.host if by_name else ip, t.port, self.a.timeout, self.a.repeat,
                           self.a.interval, self.proxy, abort=self.abort_check)
            owner = metas.get(ip)
            tag = f"AS{owner.asn} {owner.short_name}" if owner and owner.routed else ip_class(ip)
            if s.ok:
                any_ok = True
                t.conn_ip = t.conn_ip or ip
                lo, av, hi = s.stats()
                if s.flaky:
                    self.row(self.st.WN, ip, f"{s.ok}/{s.tries} 성공 — 간헐적  {av}ms ({lo}–{hi})  {tag}")
                    self.rep.add(WARN, "L4",
                                 f"{t.host}({ip}):{t.port} 연결 {s.ok}/{s.tries} 성공. "
                                 "간헐 장애 또는 일부 노드 불량.")
                else:
                    self.row(self.st.OK, ip, f"{s.ok}/{s.tries} 성공  {av}ms ({lo}–{hi})  {tag}")
            else:
                self.row(self.st.NG, ip, f"0/{s.tries}  {WHY[s.status]}  {tag}")
                where = (f"{t.host}({ip})" if t.host != ip
                         else (f"[{ip}]" if ":" in ip else ip))
                if ":" in ip and not self.proxy and not local_ip_for(ip):
                    fails.append((f"{where}:{t.port} 연결 불가 — 로컬 기기에 IPv6 경로 없음 "
                                  "(IPv6 미지원 회선).", "no_local_v6", s.status))
                    continue
                via = " (프록시 경유)" if self.proxy and s.status != PROXY_DENY else ""
                msg = {
                    REFUSED: f"{where}:{t.port} RST 응답{via}. 포트 닫힘 또는 서비스 중지.",
                    UNREACH: f"{where}:{t.port} 경로 없음{via}. 라우팅 문제.",
                    RESET: f"{where}:{t.port} 연결 직후 RST 로 끊김. 검열·IPS 장비 동작 패턴.",
                    PROXY_DENY: f"프록시가 {where}:{t.port} 연결 거부: {s.detail}",
                    LOCAL: f"{where}:{t.port} 연결이 이 기기에서 차단됨({s.detail}). 로컬 방화벽·보안 SW.",
                }.get(s.status,
                      f"{where}:{t.port} 무응답(패킷 드롭){via}. 방화벽 DROP·널 라우팅·경로 단절.")
                code = {REFUSED: "tcp_rst", LOCAL: "local_block"}.get(s.status, "tcp_fail")
                fails.append((msg, code, s.status))
        plain_http = t.scheme == "http" or (not t.scheme and t.port in (80, 8080, 8000))
        if (not any_ok and fails and self.proxy and self.proxy.scheme == "http" and plain_http
                and all(st == PROXY_DENY for _m, _c, st in fails)):
            # 평문 HTTP 는 프록시 GET 으로 동작하므로 CONNECT 거부만으로 실패 판정하지 않음
            self.row(self.st.WN, "프록시", f"{t.port} 번 CONNECT 거부 — 일반 HTTP 요청(GET)으로 확인")
            self.rep.add(INFO, "L4", f"프록시가 {t.port} 번 CONNECT 를 거부 (평문 HTTP 는 GET 요청으로 확인).")
            return True
        for msg, code, _st in fails:
            if any_ok:
                # 다른 IP 로는 연결됨 — 앱은 다른 IP 로 재시도하므로 경고로 기록
                self.rep.add(WARN, "L4", f"일부 서버 IP 실패: {msg}")
            else:
                self.rep.add(CRIT, "L4", msg, code)

        # 다른 포트를 확인해 호스트 중지와 포트 단위 차단을 구분한다.
        if not any_ok:
            alt = {443: [80, 22], 80: [443, 22]}.get(t.port, [443, 80])
            if self.a.mode == "full":
                alt += [53, 8080, 8443]
            for p in alt:
                r = tcp_probe(real[0], p, self.a.timeout, self.proxy)
                if r.ok:
                    self.row(self.st.WN, f"  ↳ :{p}", "열림 — 호스트 동작 중, 대상 포트만 차단")
                    self.rep.add(INFO, "L4",
                                 f"{real[0]}:{p} 연결됨 — 호스트 동작 중, "
                                 f"{t.port} 번만 차단.", "host_alive")
                elif r.status == REFUSED:
                    self.row(self.st.IN, f"  ↳ :{p}", "RST — 호스트 응답")
                    self.rep.add(INFO, "L4", f"{real[0]}:{p} RST 응답 — 호스트 동작 중.",
                                 "host_alive")
                else:
                    self.row(self.st.IN, f"  ↳ :{p}", WHY[r.status])
            if t.dns_suspect:
                self.probe_truth(t)
            else:
                self.probe_nodes(t)
        t.tcp_ok = any_ok
        t.meta = metas.get(t.ip)
        self._dual_stack(t, any_ok)
        self._link_shape(t, t.ip, any_ok)
        return any_ok

    def _dual_stack(self, t: Target, v4_ok: bool) -> None:
        """IPv4·IPv6 를 각각 측정한다. 앱은 두 스택을 함께 시도하므로 한쪽 장애가 지연으로 나타난다."""
        if self.a.ipv != 0:
            return
        if not t.ips6:
            self.row(self.st.IN, "IPv6", "AAAA 레코드 없음 — IPv4 전용 목적지")
            return
        v6 = t.ips6[0]
        if not self.proxy and not local_ip_for(v6):
            # 로컬에 IPv6 경로가 없으면 앱도 IPv4 만 사용하므로 지연 원인이 아님
            self.row(self.st.IN, "IPv6", "로컬 IPv6 경로 없음 — IPv4 로만 연결 (측정 생략)")
            return
        r6 = tcp_series(v6, t.port, self.a.timeout, 1, 0, self.proxy)
        t.v6_ok = bool(r6.ok)
        if r6.ok:
            self.row(self.st.OK, "IPv6", f"{v6}  열림 ({r6.stats()[1]}ms)")
        else:
            self.row(self.st.NG, "IPv6", f"{v6}  {WHY[r6.status]}")
        if v4_ok and not r6.ok:
            self.rep.add(WARN, "L4",
                         f"IPv4 연결 성공, IPv6({v6}) 실패. 앱은 두 스택을 함께 "
                         "시도하므로 간헐적 지연·실패로 나타날 수 있음.")
            self.note("앱에서만 문제가 생기는 경우 이 항목 확인")
        elif not v4_ok and r6.ok:
            self.rep.add(WARN, "L4",
                         "IPv6 연결 성공, IPv4 실패. IPv4 경로 문제 — IPv6 로 우회 가능.")

    def _link_shape(self, t: Target, ip: str, ok: bool) -> None:
        """MSS 와 TCP 홉 거리 측정 (ICMP 불필요)."""
        if not ok:
            return
        if not self.proxy:
            mss = tcp_mss(ip, t.port, self.a.timeout)
            if mss:
                t.mss = mss
                local = self.rep.data.get("mtu") or 1500
                if mss >= 1440:
                    self.row(self.st.OK, "MSS", f"{mss} — 1500 MTU 경로")
                elif mss >= 1300:
                    self.row(self.st.WN, "MSS",
                             f"{mss} — 경로 MTU 1500 미만 (터널·PPPoE·MSS clamping)")
                    self.rep.add(INFO, "L4",
                                 f"협상된 MSS {mss} (로컬 MTU {local}). "
                                 "경로상 터널 또는 중간 장비의 MSS clamping — "
                                 "큰 응답만 멈추는 증상과 관련될 수 있음.")
                else:
                    self.row(self.st.NG, "MSS", f"{mss} — 비정상적으로 작음")
                    self.rep.add(WARN, "L4",
                                 f"협상된 MSS {mss} — 매우 작음. 전송 효율 저하, "
                                 "큰 응답 분할로 인한 문제 가능.")
        t.ttl_dist = tcp_ttl_distance(ip, t.port, min(self.a.timeout, 2))
        if t.ttl_dist:
            self.row(self.st.IN, "TCP 거리", f"{t.ttl_dist}홉 (SYN TTL 측정)")

    def _by_name(self, t: Target) -> bool:
        """프록시가 이름 해석을 하므로 IP 대신 호스트명으로 연결해야 하는지."""
        return bool(self.proxy and self.proxy.remote_dns and not is_ip_literal(t.host))

    def _dest(self, t: Target) -> str:
        """연결 대상 주소: 프록시 이름 해석이면 호스트명, 아니면 검사 IP."""
        return t.host if self._by_name(t) else t.ip

    def _cert_ok(self, t: Target, ip: str) -> bool:
        """그 IP 가 t.host 이름으로 검증되는 인증서를 제공하는지 (443)."""
        info = tls_probe(t.host, ip, 443, min(self.a.timeout, 4), self.proxy)
        return bool(info.ok and info.verified and info.name_match is not False)

    def probe_truth(self, t: Target) -> None:
        """DNS 차단 시 DoH 로 얻은 IP 로 연결해 DNS 차단과 대상 차단을 구분한다."""
        cands = self._reachable(t, [ip for ip in t.truth if not is_sinkhole(ip) and ip not in t.ips])
        if not cands:
            return
        ok = 0
        for ip in cands[:3]:
            r = tcp_probe(ip, t.port, self.a.timeout, self.proxy)
            meta = cymru_bulk([ip]).get(ip)
            if r.ok:
                ok += 1
                self.row(self.st.OK, "  ↳ DoH IP",
                         f"{ip}:{t.port} 열림  ({meta.short_name if meta else ''})")
            else:
                self.row(self.st.NG, "  ↳ DoH IP", f"{ip}:{t.port} {WHY[r.status]}")
        if ok:
            self.rep.add(CRIT, "L3",
                         f"DNS 만 차단됨. DoH IP({cands[0]}):{t.port} 연결 성공 — "
                         "대상 서버는 정상.")
            self.note("DNS 설정 변경 또는 hosts 등록으로 우회 가능")
        else:
            self.rep.add(CRIT, "L3", "DNS 차단 + DoH IP 로도 연결 실패 — DNS 와 IP 이중 차단.")

    def _reachable(self, t: Target, cands: list[str]) -> list[str]:
        """로컬에 경로가 없는 주소 체계(IPv6 등)는 비교 대상에서 제외한다."""
        if self.proxy:
            return cands
        return [ip for ip in cands if ":" not in ip or local_ip_for(ip)]

    def probe_nodes(self, t: Target) -> None:
        """DNS 는 정상(CDN 등)인데 연결 실패 시, DoH 가 준 같은 서비스의 다른 IP 로 연결해 본다."""
        cands = self._reachable(t, [ip for ip in t.truth if ip not in t.ips])[:3]
        ok_ip = ""
        for ip in cands:
            r = tcp_probe(ip, t.port, self.a.timeout, self.proxy)
            self.row(self.st.OK if r.ok else self.st.IN, "  ↳ 다른 IP",
                     f"{ip}:{t.port} " + ("열림" if r.ok else WHY[r.status]))
            if r.ok and not ok_ip:
                ok_ip = ip
        if ok_ip:
            self.rep.add(WARN, "L4",
                         f"시스템 DNS 응답 IP({t.ips[0]}) 는 실패, 같은 서비스의 다른 IP({ok_ip}) 는 연결됨 — "
                         "특정 서버(노드) 장애 또는 해당 IP 단위 차단.", "node_fail")

    # ══════════ L4b · 목적지 정보 ══════════
    # 목적지 IP 의 소유자·대역·RPKI 확인.
    def l4b_identity(self, t: Target) -> None:
        if self.a.mode == "quick" or not t.ips or is_sinkhole(t.ip):
            return
        ip = t.ip
        self.sect("L4b · 목적지 정보 — IP 소유자·대역")
        meta = t.meta or cymru_bulk([ip]).get(ip) or IpMeta(ip)
        if not meta.routed:
            # Cymru 조회 실패 시 RIPE stat 으로 재조회한다.
            alt = ripe_netinfo(ip, max(self.a.timeout, 10), self.proxy)
            if alt and alt.routed:
                alt.as_name = alt.as_name or f"AS{alt.asn}"
                meta = alt
                self.note("Cymru 응답 없음 — RIPE stat 으로 조회")
        f_ptr = self.pool.submit(ptr_lookup, ip)
        f_rir = self.pool.submit(rir_lookup, ip, meta.registry)
        meta.ptr = f_ptr.result()
        rir = f_rir.result()
        t.meta = meta

        self.row(self.st.IN, "주소", f"{ip}  ({ip_class(ip)})")
        if meta.ptr:
            # PTR 은 임의로 설정할 수 있으므로 정방향(DoH) 조회로 일치 여부를 확인한다.
            fwd = doh_query(meta.ptr, "A", self.a.timeout, self.proxy)
            addrs = fwd.addrs if fwd else []
            if ip in addrs:
                self.row(self.st.OK, "역방향 이름", f"{meta.ptr}  (정방향 조회 일치)")
            elif not addrs:
                self.row(self.st.IN, "역방향 이름", f"{meta.ptr}  (정방향 확인 불가)")
            else:
                self.row(self.st.WN, "역방향 이름",
                         f"{meta.ptr}  (정방향 {' '.join(addrs[:3])} — 불일치)")
        else:
            self.row(self.st.IN, "역방향 이름", "없음")

        if meta.routed:
            self.row(self.st.IN, "AS", f"AS{meta.asn}  {meta.short_name}")
            self.row(self.st.IN, "BGP 대역",
                     f"{meta.prefix}  (국가 {meta.cc}, 등록 {meta.registry}, 할당 {meta.allocated})")
        elif meta.asn == "NA":
            self.row(self.st.NG, "AS", "없음 — BGP 미광고 주소")
        else:
            self.row(self.st.WN, "AS", "조회 불가")
        if rir.get("netname"):
            rng = f"   ({rir['range']})" if rir.get("range") else ""
            self.row(self.st.IN, "등록 대역명", rir["netname"] + rng)
        if rir.get("org"):
            cc = f"  [{rir['country']}]" if rir.get("country") else ""
            self.row(self.st.IN, "사용 주체", rir["org"] + cc)
        if rir.get("abuse"):
            self.row(self.st.IN, "신고처", rir["abuse"])
        # RPKI 로 광고 AS 의 정당성 확인.
        if meta.routed and self.a.mode != "quick":
            st_, desc = rpki_validate(meta.asn, meta.prefix, self.a.timeout, self.proxy)
            t.rpki = st_
            if st_ == "valid":
                self.row(self.st.OK, "경로 출처(RPKI)",
                         f"valid — AS{meta.asn} 가 {meta.prefix} 의 정당한 광고자")
            elif st_ == "invalid":
                self.row(self.st.NG, "경로 출처(RPKI)",
                         f"invalid — AS{meta.asn} 는 {meta.prefix} 광고 권한 없음")
                self.rep.add(CRIT, "L4b",
                             f"{meta.prefix} 를 AS{meta.asn} 가 광고 중이나 RPKI invalid — "
                             "경로 하이재킹 의심. 연결 대상이 실제 소유자가 아닐 수 있으므로 "
                             "인증서 확인 필요.")
            elif st_ == "unknown":
                self.row(self.st.IN, "경로 출처(RPKI)",
                         "unknown — ROA 미등록")
            else:
                self.row(self.st.IN, "경로 출처(RPKI)", f"확인 불가 ({desc})")

        self.row(self.st.IN, "성격", ip_kind(meta))
        if len(t.ips) > 1:
            self.row(self.st.IN, "서버 대수", f"{len(t.ips)}개 주소로 분산 — 일부 서버만 장애일 수 있음")

        if self.a.mode == "full":
            self.port_sweep(ip)

    def port_sweep(self, ip: str) -> None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443]
        res = list(self.pool.map(
            lambda p: (p, tcp_probe(ip, p, self.a.timeout, self.proxy)), ports))
        opened = [str(p) for p, r in res if r.ok]
        closed = [str(p) for p, r in res if r.status == REFUSED]
        if opened:
            self.row(self.st.OK, "열린 포트", " ".join(opened))
        if closed:
            self.row(self.st.IN, "닫힌 포트", " ".join(closed) + "  (RST — 호스트 응답)")
        if not opened and not closed:
            self.note("모든 포트 무응답 — 호스트 중지 또는 전면 차단")
        elif not opened:
            self.note("모든 포트 RST — 호스트는 동작 중, 열린 서비스 없음")

    # ══════════ L5 · TLS ══════════
    def l5_tls(self, t: Target) -> Optional[TlsInfo]:
        if t.scheme == "http":
            return None
        if (t.scheme != "https" and t.port not in (443, 8443, 993, 995, 465, 587, 853)
                and self.a.mode != "full"):
            return None
        if not t.ips:
            return None
        self.sect("L5 · TLS — 인증서·협상")
        info = tls_probe(t.host, self._dest(t), t.port, self.a.timeout, self.proxy)
        if not info.ok:
            self.row(self.st.NG, "핸드셰이크", f"실패 — {trunc(info.error, 70)}")
            self.rep.add(CRIT, "L5",
                         f"{t.host}:{t.port} TLS 핸드셰이크 실패. TCP 연결은 성공했으므로 "
                         "SNI 차단·중간자·TLS 버전 불일치 확인 필요.")
            # SNI 없이 재시도. 성공하면 SNI 기반 차단.
            bare = tls_probe(t.host, self._dest(t), t.port, self.a.timeout, self.proxy, sni=False)
            if bare.ok:
                self.row(self.st.NG, "SNI 차단", "SNI 없이는 핸드셰이크 성공 — 호스트명 기반 차단")
                self.rep.add(CRIT, "L5",
                             "SNI 기반 차단. 중간 장비가 ClientHello 의 호스트명으로 연결을 끊음.")
            return info

        self.row(self.st.OK, "핸드셰이크",
                 f"{info.version}  {info.cipher}" + (f"  ALPN={info.alpn}" if info.alpn else ""))
        if info.version in ("TLSv1", "TLSv1.1", "SSLv3"):
            self.row(self.st.WN, "버전", f"{info.version} — 지원 중단된 구형 프로토콜")
        if info.verified:
            self.row(self.st.OK, "검증", "시스템 신뢰 저장소로 검증됨")
        elif is_ip_literal(t.host):
            # IP 로 접속하면 SNI 가 없어 서버가 기본 인증서를 주므로 검증 실패가 일반적
            self.row(self.st.IN, "검증", f"{trunc(info.error or '검증 실패', 50)} — IP 접속(SNI 없음)의 기본 인증서")
        else:
            self.row(self.st.NG, "검증", trunc(info.error or "검증 실패", 70))
            self.rep.add(CRIT, "L5", f"인증서 검증 실패: {trunc(info.error, 80)}")
        if info.not_after:
            left = info.days_left
            state = ("만료됨" if left is not None and left < 0 else
                     f"{left}일 남음" if left is not None and left < 30 else "유효")
            self.row(self.mark(state == "유효" or "일 남음" in state,
                               warn="일 남음" in state), "유효기간",
                     f"{info.not_after}  ({state})")
            if left is not None and left < 0:
                self.rep.add(CRIT, "L5", f"{t.host} 인증서 만료됨 ({info.not_after}).")
            elif left is not None and left < 14:
                self.rep.add(WARN, "L5", f"{t.host} 인증서 {left}일 후 만료.")
        if info.issuer:
            self.row(self.st.IN, "발급자", trunc(info.issuer, 66))
        if info.name_match is True:
            self.row(self.st.OK, "이름 일치", f"{t.host} 포함")
        elif info.name_match is False:
            if is_ip_literal(t.host):
                self.row(self.st.IN, "이름 일치", f"{t.host} 미포함 — IP 로 접속했으므로 정상")
            else:
                self.row(self.st.NG, "이름 일치", f"{t.host} 미포함 — 다른 서버 연결 또는 중간자")
                self.rep.add(CRIT, "L5", f"인증서 이름이 {t.host} 와 불일치.")
        if info.sans:
            extra = f" …({len(info.sans)}개)" if len(info.sans) > 6 else ""
            self.row(self.st.IN, "인증서 이름", trunc(" ".join(info.sans[:6]), 62) + extra)
        low = info.issuer.lower()
        if any(v in low for v in MITM_VENDORS):
            self.row(self.st.NG, "가로채기 장비", "발급자가 TLS 검사 제품 — 중간에서 복호화됨")
            self.rep.add(CRIT, "L5",
                         f"TLS 중간 복호화(발급자: {trunc(info.issuer, 60)}). "
                         "방화벽·백신의 SSL 검사 기능.")
        return info

    # ══════════ L5b · 인증서 이력 (CT 로그) ══════════
    def l5b_ct(self, t: Target, tls: Optional[TlsInfo]) -> None:
        if not self.a.ct or not tls or not tls.ok:
            return
        if is_ip_literal(t.host):
            return
        self.sect("L5b · 인증서 이력 — 공개 CT 로그(crt.sh) 대조")
        self.note("crt.sh 에 도메인 이름을 전송함 — 사내 전용 도메인이면 주의")
        dom = registrable(t.host)
        ct = ct_lookup(dom, tls.serial, self.a.timeout, self.proxy)
        if not ct.reachable:
            self.row(self.st.WN, "조회", f"crt.sh 조회 실패 — {trunc(ct.error, 50)}")
            self.note("조회 실패이므로 판정에 반영하지 않음")
            return

        # ① 받은 인증서의 CT 등록 여부. crt.sh 색인은 지연될 수 있으므로
        #    미등록만으로 판정하지 않고 발급자 이력과 함께 본다.
        served = issuer_key(tls.issuer)
        hist_issuers = {i.lower() for i in ct.issuers}
        known_public = is_public_ca(tls.issuer)
        in_history = (any(served in h or h in served for h in hist_issuers)
                      if (ct.hist_ok and hist_issuers) else None)

        # 주체 = 발급자면 자체 서명. CT 등록 대상이 아니므로 CT 판정에서 제외한다.
        self_signed = bool(tls.subject and tls.subject == tls.issuer)
        if self_signed:
            self.row(self.st.NG, "현재 인증서", "자체 서명 — CA 발급 아님")
            self.note("자체 서명은 CT 등록 대상 아님. 내부용이면 정상, 공개 서비스면 설정 오류")
            self.rep.add(WARN, "L5b", "자체 서명 인증서. 공개 CA 발급 아님.")
        elif ct.serial_found is True:
            e = ct.serial_entry
            self.row(self.st.OK, "현재 인증서",
                     f"CT 로그 등록 확인 (crt.sh id={e.get('id')})")
        elif ct.serial_found is False:
            if known_public or in_history:
                # 공개 CA 또는 이력상 발급자 — 색인 지연으로 처리.
                self.row(self.st.IN, "현재 인증서",
                         "CT 미확인 — 발급자는 공개 CA. 색인 지연 가능")
                self.note(f"발급일 {tls.not_before[:12] or '?'} — 최근 발급이면 미색인 상태일 수 있음")
            elif in_history is False:
                # 이력에 없는 발급자이고 주요 공개 CA 도 아님.
                self.row(self.st.NG, "현재 인증서",
                         "CT 미등록, 이력에 없는 발급자")
                self.rep.add(CRIT, "L5b",
                             f"인증서 발급자({trunc(served, 40)})가 CT 이력에 없고 인증서도 CT 미등록 — "
                             "TLS 가로채기(중간 재서명) 의심.")
                self.note(f"이력상 발급자: {trunc(', '.join(ct.issuers[:3]), 60)}")
            else:
                self.row(self.st.WN, "현재 인증서", "CT 미확인 (비교할 이력 없음)")
                self.rep.add(WARN, "L5b",
                             "인증서 CT 미확인, 비교할 발급 이력 없음. "
                             "사설 CA 발급 또는 내부 전용 도메인일 수 있음.")

        # ② 발급자 이력 비교 (색인 지연과 무관).
        if in_history is False and ct.serial_found is not True:
            self.row(self.st.WN, "발급자 변경",
                     f"현재 발급자 '{trunc(served, 28)}' 이력에 없음")

        if not ct.hist_ok:
            self.row(self.st.WN, "발급 이력",
                     f"조회 실패 — {trunc(ct.error, 46)}")
            self.note("조회 실패 — 발급자 비교 생략")
        elif not ct.history:
            self.row(self.st.IN, "발급 이력", "없음 — 공개 CA 발급 기록 없음")
        if ct.history:
            newest = max((e.get("not_before") or "") for e in ct.history)
            self.row(self.st.IN, "발급 이력", f"{len(ct.history)}건, 최근 {newest[:10]}")
            # 최근 7일 내 발급 표시.
            try:
                days = (time.time() - time.mktime(time.strptime(newest[:10], "%Y-%m-%d"))) / 86400
                if 0 <= days <= 7:
                    self.row(self.st.IN, "최근 발급",
                             f"{int(days)}일 전 신규 발급 (정기 갱신 여부 확인)")
            except (ValueError, OverflowError):
                pass
            if ct.issuers:
                self.row(self.st.IN, "발급자 이력",
                         trunc(", ".join(ct.issuers), 66)
                         + (f"  ({len(ct.issuers)}곳)" if len(ct.issuers) > 1 else ""))
            if ct.names:
                extra = f"  …총 {len(ct.names)}개" if len(ct.names) > 5 else ""
                self.row(self.st.IN, "로그에 남은 이름",
                         trunc(" ".join(ct.names[:5]), 62) + extra)
                self.note("CT 는 공개 기록 — 내부용 서브도메인도 노출됨")


    # ══════════ L6 · HTTP ══════════
    def l6_http(self, t: Target) -> None:
        scheme = t.scheme or ("https" if t.port in (443, 8443) else "http")
        if (not t.scheme and t.port not in (80, 443, 8080, 8443, 8000)
                and self.a.mode != "full"):
            return
        if not t.ips:
            return
        self.sect("L6 · HTTP — 서버 응답")
        h = http_probe(t.host, self._dest(t), t.port, self.a.timeout, scheme,
                       self.proxy, path=t.path)
        if t.path != "/":
            self.row(self.st.IN, "확인한 경로", t.path)
        if not h.ok:
            self.row(self.st.NG, "요청", f"실패 — {trunc(h.error, 70)}")
            if h.timed_out:
                self.rep.add(CRIT, "L6",
                             f"{scheme}://{t.host}:{t.port} TCP 연결 후 HTTP 응답 없음 "
                             f"({self.a.timeout:g}초 타임아웃). 서버 미응답 또는 중간 장비의 HTTP 차단.",
                             "http_timeout")
            else:
                self.rep.add(CRIT, "L6", f"{scheme}://{t.host}:{t.port} 요청 실패: {trunc(h.error, 60)}")
            return
        if h.code == 0:
            # 요청은 전송됐으나 상태줄 없이 연결 종료 (nginx 444, DPI 장비의 FIN 등)
            self.row(self.st.NG, "응답", "없음 — 서버가 응답 없이 연결 종료")
            self.rep.add(CRIT, "L6",
                         f"{scheme}://{t.host}:{t.port} HTTP 응답 없음 — 요청 후 연결이 종료됨. "
                         "서버 거부 또는 중간 장비의 HTTP 차단.", "http_timeout")
            return

        # 누적 시간이 아닌 구간별 소요 시간으로 표시한다.
        tls_seg = h.t_tls - h.t_connect if h.t_tls else 0
        wait = h.t_ttfb - (h.t_tls or h.t_connect)
        for label, val, tail in (("TCP", h.t_connect, ""),
                                 ("TLS", tls_seg, ""),
                                 ("서버 대기", wait, "  (서버 처리 시간)"),
                                 ("본문 수신", h.t_total - h.t_ttfb, "")):
            if label == "TLS" and not tls_seg:
                continue
            self.row(self.st.IN, label, f"{max(val, 0):5d} ms{tail}")
        self.row(f"{self.st.B}{self.st.g('━')}{self.st.RST}", "합계", f"{h.t_total:5d} ms")

        good = 200 <= h.code < 400
        self.row(self.mark(good, warn=(400 <= h.code < 500 and h.code not in (401, 403, 429))),
                 "응답", f"HTTP {h.code}  (HTTP/{h.version}, {h.size}B, "
                        f"이동 {len([c for c in h.chain if c.location])}회, 서버IP {t.ip})")
        if h.code in (401, 403):
            self.rep.add(CRIT, "L6", f"HTTP {h.code} — 인증·권한 거부. 네트워크 정상, 키·토큰·허용목록 확인 필요.")
        elif h.code == 429:
            self.rep.add(CRIT, "L6", "HTTP 429 — 호출 한도 초과. 차단이 아닌 사용량 제한.")
        elif h.code >= 500:
            self.rep.add(CRIT, "L6", f"HTTP {h.code} — 서버 오류. 서버 측 문제.")

        moves = [st for st in h.chain if st.location]
        if moves:
            self.row(self.st.IN, "이동 경로", f"{len(moves)} 단계")
            for i, step in enumerate(moves, 1):
                if not self.a.json:
                    print(f"        {i}) {step.code} → {trunc(step.location, 66)}")
        if h.redirect_error and h.redirect_sinkhole:
            # 서버 응답은 정상, 이동 대상 이름이 로컬 DNS 에서 차단됨
            self.row(self.st.NG, "이동 실패", trunc(h.redirect_error, 66))
            self.rep.add(CRIT, "L3",
                         f"리다이렉트 대상 이름이 DNS 에서 차단됨: {trunc(h.redirect_error, 70)}. "
                         "서버 응답은 정상.")
        elif h.redirect_error:
            self.row(self.st.NG, "이동 실패", trunc(h.redirect_error, 66))
            self.rep.add(CRIT, "L6",
                         f"첫 응답 수신, 리다이렉트 대상 연결 실패: {trunc(h.redirect_error, 70)}")
        if h.server:
            self.row(self.st.IN, "Server", trunc(h.server, 60))
        if h.proxy_hdrs:
            self.row(self.st.IN, "중간 경유",
                     trunc(" ".join(f"{k}={v}" for k, v in h.proxy_hdrs.items()), 68))
            self.note("원본 서버가 아닌 캐시·프록시 응답일 수 있음")
        if "h3" in h.alt_svc and not h.version.startswith("3"):
            self.row(self.st.IN, "HTTP/3", f"서버가 h3 광고, 실제 연결은 HTTP/{h.version}")

        # 200 응답이라도 본문이 거절 안내인지 확인한다.
        peek = " ".join(h.body_head.split())
        em = ERRFIELD_PAT.search(peek)
        msg = next((g for g in (em.groups() if em else ()) if g), "")
        if msg:
            self.row(self.st.NG, "서버 메시지", trunc(msg, 66))
        if DENY_PAT.search(visible_text(h.body_head)):
            self.rep.add(CRIT, "L6",
                         f"HTTP {h.code}, 본문이 거절 응답"
                         + (f" — {msg}" if msg else "")
                         + ". 네트워크 정상, 애플리케이션 계층 차단.")

    # ══════════ L6b · URL 변형 ══════════
    # https·http × www 유무 조합으로 요청해 입력한 주소와 다른 주소의 응답을 비교한다.
    def l6b_variants(self, t: Target) -> None:
        if (self.a.mode == "quick" or not self.a.variants or is_ip_literal(t.host)
                or t.port not in (80, 443)):
            return
        variants = url_variants(t.host, t.path)
        main = (t.scheme or ("https" if t.port == 443 else "http"), t.host)
        self.sect("L6b · URL 변형 — https·http·www 조합 응답")
        res = list(self.pool.map(
            lambda v: (v, self._try_url(*v, t.path)), variants))
        rows = []
        for (sch, host), r in res:
            url = f"{sch}://{host}{t.path if t.path != '/' else ''}"
            tag = "  (입력)" if (sch, host) == main else ""
            rows.append({"url": url, "input": bool(tag), **r})
            # 실패 표시(✘)는 입력한 주소만. 다른 조합의 실패는 참고용 경고(⚠)
            mark = (self.st.OK if r["works"] else self.st.IN if r["kind"] == "noname"
                    else self.st.NG if tag else self.st.WN)
            self.row(mark, trunc(url, 34) + tag, r["text"])
        self.rep.data.setdefault("variants", {})[t.key] = rows

        by = {(sch, host): r for (sch, host), r in res}
        m = by.get(main)
        ok = [(v, r) for v, r in res if r["works"]]
        if m and not m["works"] and ok:
            (sch, host), r = ok[0]
            if host != main[1] and sch == main[0]:
                hint = "www 유무에 따라 DNS·서버 설정이 다름 — 응답하는 주소 사용 또는 DNS 레코드 확인"
            elif sch == "http" and main[0] == "https":
                hint = "HTTPS(443) 미지원 또는 차단, HTTP(80) 는 응답"
            elif sch == "https" and main[0] == "http":
                hint = "HTTP(80) 미지원 또는 차단, HTTPS(443) 는 응답"
            else:
                hint = "응답하는 주소 사용 또는 서버 설정 확인"
            self.rep.add(WARN, "L6b",
                         f"입력한 {main[0]}://{main[1]} 는 실패, {sch}://{host} 는 응답({r['code']}) — {hint}.",
                         "variant_ok")
        elif m and m["works"]:
            bad = [f"{sch}://{host}" for (sch, host), r in res
                   if not r["works"] and r["kind"] != "noname"]
            if bad:
                self.rep.add(INFO, "L6b", f"입력한 주소는 정상, 실패한 변형: {', '.join(bad)}.")
            plain = by.get(("http", main[1]))
            if plain and plain["works"] and not plain["to_https"]:
                self.rep.add(INFO, "L6b",
                             f"http://{main[1]} 가 HTTPS 로 이동하지 않음 (평문 HTTP 접속 허용).")

    def _try_url(self, scheme: str, host: str, path: str) -> dict:
        """한 URL 요청 결과 요약."""
        port = 443 if scheme == "https" else 80
        if self.proxy and self.proxy.remote_dns:
            ip = ""
        else:
            addrs = os_resolve(host)
            if not addrs:
                return {"works": False, "kind": "noname", "code": 0, "final": "",
                        "to_https": False, "text": "이름 해석 실패 (주소 없음)"}
            ip = addrs[0]
            if is_sinkhole(ip):
                return {"works": False, "kind": "sinkhole", "code": 0, "final": "",
                        "to_https": False, "text": f"{ip} — 싱크홀 주소 (DNS 차단)"}
        h = http_probe(host, ip, port, self.a.timeout, scheme, self.proxy, path=path)
        if not h.ok or h.code == 0:
            why = "응답 없음 (연결 종료)" if h.ok else trunc(h.error or "연결 실패", 40)
            return {"works": False, "kind": "fail", "code": 0, "final": "",
                    "to_https": False, "text": f"실패 — {why}"}
        codes = " → ".join(str(st.code) for st in h.chain) or str(h.code)
        final = h.final_url if len(h.chain) > 1 else ""
        works = 0 < h.code < 500 and not h.redirect_error
        text = f"{codes}  {h.t_total}ms"
        if final:
            text += f"  → {trunc(final, 40)}"
        if h.redirect_error:
            text += f"  (이동 실패: {trunc(h.redirect_error, 44)})"
        return {"works": works, "kind": "http", "code": h.code, "final": final,
                "to_https": any(st.location.lower().startswith("https://") for st in h.chain),
                "text": text}

    # ══════════ L7 · 경로 ══════════
    def l7_path(self, t: Target) -> None:
        if not self.a.trace or not t.ips or is_sinkhole(t.ip):
            return
        ip = t.ip
        self.sect("L7 · 경로 — 홉별 도달 구간·소유자")
        if self.proxy:
            # ICMP·UDP 는 CONNECT 터널로 전달되지 않으므로 직접 경로가 측정된다.
            self.row(self.st.WN, "주의",
                     "traceroute 는 프록시를 경유할 수 없음")
            self.note("아래 경로는 프록시 경로가 아닌 직접 연결 경로")
            self.note("프록시 이후 경로는 프록시 서버에서 측정 필요")

        self.ck()
        hops, mode = traceroute(ip, self.a.max_hop, self.a.probes,
                                self.a.max_hop * self.a.probes + 20)
        if not hops:
            self._path_blocked(t, ip)
            return
        if mode == "ICMP":
            self.note("UDP 응답 없음 — ICMP 로 전환")

        metas = self._hop_meta(hops)
        aspath, jump, jump_at, jump_pair, last_ip, last_n = self._render_hops(hops)
        self._judge_loss(t, hops, ip)

        if aspath:
            txt = " → ".join(f"AS{a} {trunc(o, 22)} ({s0}~{e}홉)" for a, o, s0, e in aspath)
            self.row(self.st.IN, "AS 경로", f"[로컬] → {txt}")
            self.rep.data.setdefault("as_path", {})[t.key] = txt
        if jump > 10:
            pair = (f"  (AS{jump_pair[0]} → AS{jump_pair[1]} 경계)"
                    if jump_pair[0] not in ("", "-") and jump_pair[1] != "-"
                    and jump_pair[0] != jump_pair[1] else "")
            self.row(self.st.IN, "최대 지연 증가", f"{jump_at}홉에서 +{jump:.1f}ms{pair}")

        self._reverse_path(ip, last_n)
        self.rep.data.setdefault("last_hop", {})[t.key] = last_ip
        self.rep.data.setdefault("dest_ip", {})[t.key] = ip
        self.rep.data.setdefault("hops", {})[t.key] = hops
        self._judge_interception(t, ip, last_ip, last_n)
        self._judge_destination(t, ip, last_ip, last_n, metas)

    def _path_blocked(self, t: Target, ip: str) -> None:
        """traceroute 응답이 전혀 없을 때. TCP 로 홉 거리만 측정한다."""
        self.row(self.st.NG, "traceroute", "전 홉 무응답 — ICMP/UDP 차단된 네트워크")
        d = t.ttl_dist or tcp_ttl_distance(ip, t.port, min(self.a.timeout, 2))
        if d:
            self.row(self.st.OK, "TCP 거리", f"{d}홉 (TCP SYN TTL 측정)")
            self.note("홉 주소는 알 수 없음. 거리 비교용")
        else:
            self.note(f"TCP traceroute 시도: sudo traceroute -n -P TCP -p {t.port} {ip}")

    def _hop_meta(self, hops: list[Hop]) -> MetaSet:
        """홉 소유자·PTR 을 일괄 조회한다."""
        addrs = [h.ip for h in hops if h.ips]
        metas = cymru_bulk(addrs)
        ptrs = dict(zip(addrs, self.pool.map(ptr_lookup, addrs)))
        for h in hops:
            if h.ips:
                h.meta = metas.get(h.ip, IpMeta(h.ip))
                h.meta.ptr = ptrs.get(h.ip, "")
        return metas

    def _render_hops(self, hops: list[Hop]):
        """홉 표를 그리고 (AS 경로, 최대 지연 증가, 마지막 응답 홉) 을 돌려준다."""
        if not self.a.json:
            print(f"{self.st.DIM}    홉  주소                 RTT    증가   응답  AS"
                  f"        소유자{self.st.RST}")
        prev_rtt: Optional[float] = None
        prev_as = ""
        jump, jump_at, jump_pair = 0.0, 0, ("", "")
        aspath: list[tuple[str, str, int, int]] = []
        last_ip, last_n = "", 0

        for h in hops:
            if not h.ips:
                self.emit("hop", n=h.n, ip="*", rtt=None, delta="", recv=h.recv,
                          sent=h.sent, asn="-", owner="", ptr="", edge=False, ecmp=False)
                if not self.a.json:
                    print(f"  {self.st.IN} {str(h.n):<3} {self.st.DIM}무응답 (라우터의 ICMP 미응답일 수 있음)"
                          f"{self.st.RST}")
                continue

            meta = h.meta or IpMeta(h.ip)
            asn = meta.asn if meta.routed else "-"
            owner = meta.short_name if meta.routed else ip_class(h.ip)
            delta = ""
            if prev_rtt is not None and h.rtt is not None:
                d = h.rtt - prev_rtt
                delta = f"{d:+.1f}"
                if d > jump:
                    jump, jump_at, jump_pair = d, h.n, (prev_as, asn)
            if h.rtt is not None:
                prev_rtt = h.rtt

            edge = bool(prev_as and asn != "-" and prev_as != "-" and asn != prev_as)
            if asn != "-":
                if aspath and aspath[-1][0] == asn:
                    aspath[-1] = (asn, owner, aspath[-1][2], h.n)
                else:
                    aspath.append((asn, owner, h.n, h.n))
                prev_as = asn

            self.emit("hop", n=h.n, ip=h.ip, rtt=h.rtt, delta=delta, recv=h.recv,
                      sent=h.sent, asn=asn, owner=owner, ptr=meta.ptr,
                      edge=edge, ecmp=h.ecmp)
            if not self.a.json:
                print(f"  {self.st.WN if edge else self.st.OK} {str(h.n):<3} "
                      f"{h.ip:<16} {(f'{h.rtt:.3f}' if h.rtt is not None else '-'):>8} "
                      f"{delta:>6} {f'{h.recv}/{h.sent}':>6}  "
                      f"{('AS' + asn if asn != '-' else '-'):<9} "
                      f"{pad(trunc(owner + (' ECMP' if h.ecmp else ''), 26), 26)} "
                      f"{self.st.WNC + '← AS 경계' + self.st.RST if edge else ''}")
                if meta.ptr:
                    print(f"        {self.st.DIM}{self.st.g('↳')} {meta.ptr}{self.st.RST}")
            last_ip, last_n = h.ip, h.n

        self.note("응답: 홉별 응답 프로브 수 / 전송 수. ECMP: 다중 경로 홉")
        self.note("RTT: ms(최소값). 증가 값의 음수는 라우터 ICMP 처리 지연 차이로 정상 범위")
        return aspath, jump, jump_at, jump_pair, last_ip, last_n

    def _judge_loss(self, t: Target, hops: list[Hop], dest_ip: str) -> None:
        """중간 홉 손실은 ICMP 응답 제한일 수 있으므로 마지막 홉까지 이어질 때만 경로 손실로 판정한다."""
        answered = [h for h in hops if h.ips]
        if not answered or not any(h.recv < h.sent for h in answered):
            return
        end = answered[-1]
        if end.ip != dest_ip:
            self.row(self.st.IN, "중간 손실",
                     "있음 — 경로가 목적지에 도달하지 않아 판정 보류")
        elif end.recv == end.sent:
            self.row(self.st.IN, "중간 손실",
                     f"있음 — 마지막 홉 {end.recv}/{end.sent}, ICMP 응답 제한 (경로 손실 아님)")
        elif t.tcp_ok or end.sent - end.recv <= 1:
            # TCP 정상이거나 프로브 1개만 손실: 목적지의 ICMP 응답 제한일 수 있어 경로 손실로 단정하지 않음
            self.row(self.st.WN, "목적지 손실",
                     f"마지막 홉 {end.recv}/{end.sent} — ICMP 응답 일부 누락"
                     + (" (TCP 연결 정상)" if t.tcp_ok else ""))
            self.rep.add(INFO, "L7",
                         f"목적지 ICMP 응답 일부 누락({end.recv}/{end.sent}). "
                         "응답 제한 가능 — 반복 측정(-f, --watch)으로 확인.")
        else:
            self.row(self.st.NG, "경로 손실",
                     f"마지막 홉 {end.recv}/{end.sent} — 경로상 패킷 손실")
            self.rep.add(CRIT, "L7",
                         f"목적지까지 패킷 손실({end.recv}/{end.sent}). "
                         "회선 품질 또는 혼잡 문제.")

    def _reverse_path(self, ip: str, fwd_hops: int) -> None:
        """응답 TTL 로 역방향 홉 수를 추정한다."""
        _l, _a, ttl = ping(ip, 2)
        if not ttl or not fwd_hops:
            return
        init = 64 if ttl <= 64 else (128 if ttl <= 128 else 255)
        rhops = init - ttl
        if rhops <= 0:
            return
        if abs(fwd_hops - rhops) >= 3:
            self.row(self.st.WN, "역경로",
                     f"역방향 {rhops}홉, 정방향 {fwd_hops}홉 — 비대칭 경로")
            self.note("역방향 경로 장애는 traceroute 로 확인 불가")
            self.rep.add(INFO, "L7",
                         f"비대칭 경로(정방향 {fwd_hops}홉, 역방향 {rhops}홉). "
                         "역방향 장애는 이 위치에서 측정 불가.")
        else:
            self.row(self.st.IN, "역경로", f"역방향 약 {rhops}홉 (정방향 {fwd_hops}홉)")

    def _judge_interception(self, t: Target, ip: str, last_ip: str, last_n: int) -> None:
        """TCP 연결 거리가 경로 거리보다 짧으면 중간 장비의 대리 응답으로 판정한다."""
        if not (t.ttl_dist and last_n and t.tcp_ok and last_ip == ip):
            return
        if last_n - t.ttl_dist < 3:
            return
        self.row(self.st.NG, "중간 응답",
                 f"경로 {last_n}홉, TCP 연결 {t.ttl_dist}홉")
        self.rep.add(CRIT, "L4",
                     f"목적지 {last_n}홉, TCP 연결은 {t.ttl_dist}홉에서 성립 — "
                     "중간 장비가 목적지 대신 응답(투명 프록시·가로채기).", "intercept")
        self.note("응답 주체가 목적지 서버가 아닐 수 있음 — TLS 인증서 확인")

    def _judge_destination(self, t: Target, ip: str, last_ip: str,
                           last_n: int, metas: MetaSet) -> None:
        if last_ip == ip:
            self.row(self.st.OK, "도달", f"목적지 도달 ({last_n}홉)")
            return
        if last_n >= self.a.max_hop:
            # 최대 홉 제한에서 끝남 — 중단 지점이 아니므로 판정하지 않는다
            dist = f", TCP 거리 {t.ttl_dist}홉" if t.ttl_dist else ""
            self.row(self.st.WN, "도달", f"최대 홉({self.a.max_hop}) 도달 — 목적지까지 측정 안 됨{dist}")
            self.note("-m 값을 늘려 재검사")
            return
        if t.tcp_ok:
            # TCP 연결 성공 시 경로는 정상. traceroute 중단은 ICMP·UDP 필터링.
            self.row(self.st.OK, "도달", f"traceroute 는 {last_n}홉까지, TCP 는 도달")
            self.note("목적지 또는 중간 장비의 ICMP·UDP 필터링. 경로 문제 아님")
            self.rep.add(INFO, "L7",
                         f"traceroute 는 {last_n}홉에서 중단, TCP 는 성공 — "
                         "ICMP/UDP 필터링. 경로 정상.")
            return

        lm = metas.get(last_ip, IpMeta(last_ip))
        dm = cymru_bulk([ip]).get(ip, IpMeta(ip))

        def owner_of(mt: IpMeta, addr: str) -> str:
            if mt.routed:
                return f"AS{mt.asn} {mt.short_name}"
            return ip_class(addr) if is_private(addr) else "소유자 확인 불가"

        self.row(self.st.NG, "마지막 응답",
                 f"{last_n}홉 {last_ip}  [{owner_of(lm, last_ip)}]")
        self.row(self.st.IN, "목적지", f"{ip}  [{owner_of(dm, ip)}]")
        if is_private(last_ip):
            self.rep.add(CRIT, "L7",
                         f"마지막 응답 {last_n}홉({last_ip})이 사설 대역 — ISP 내부 구간에서 중단. "
                         "통신사 확인 필요.")
        elif lm.asn == dm.asn and lm.routed:
            self.rep.add(CRIT, "L7",
                         f"마지막 응답 홉과 목적지가 같은 AS({lm.asn}) — 목적지 네트워크 내부에서 중단.")
        else:
            self.rep.add(CRIT, "L7",
                         f"{last_ip}(AS{lm.asn}) 이후 중단. 이 홉과 목적지 "
                         f"AS({dm.asn}) 사이 구간 문제.")
        self.note(f"{last_ip} 는 마지막 응답 홉 — 문제 구간은 그 다음 홉부터")

    # ══════════ L7b · 경로 비교 ══════════
    # 실패 목적지와 정상 대조군의 경로를 비교해 공통 구간과 분기 지점을 찾는다.
    # 공통 구간은 대조군이 정상이므로 원인에서 제외한다.
    def l7b_diff(self, t: Target) -> None:
        if not self.a.trace or t.tcp_ok:
            return                      # 연결된 목적지는 비교 생략
        mine = self.rep.data.get("hops", {}).get(t.key) or []
        base_ip = next((x for x in self.rep.data.get("baseline_ok", [])
                        if x not in t.ips), None)
        if not mine or not base_ip:
            return
        self.sect("L7b · 경로 비교 — 정상 대조군과 분기 지점")
        self.ck()
        theirs, _mode = traceroute(base_ip, self.a.max_hop, self.a.probes,
                                   self.a.max_hop * self.a.probes + 20)
        if not theirs:
            self.row(self.st.WN, "기준 경로", f"{base_ip} 경로 측정 실패 — 비교 불가")
            return

        by_n = {h.n: h for h in theirs}
        same, shared = 0, ""
        for h in mine:
            o = by_n.get(h.n)
            if not o:
                break
            # ECMP 홉은 IP 중 하나라도 겹치면 같은 지점. 무응답(*) 홉은 비교에서 건너뛴다.
            if not h.ips or not o.ips:
                continue
            if set(h.ips) & set(o.ips):
                same, shared = h.n, h.ip
            else:
                break
        if same:
            self.row(self.st.OK, "공통 구간",
                     f"1~{same}홉이 정상 경로와 동일 ({shared} 까지)")
            self.note("이 구간(로컬·게이트웨이·ISP 진입)은 정상")
            self.rep.add(INFO, "L7",
                         f"정상 대조군({base_ip})과 {same}홉까지 경로 동일. "
                         "해당 구간(게이트웨이·ISP 진입)은 정상.")
        else:
            self.row(self.st.WN, "공통 구간", "첫 홉부터 다름 — 공통 구간 없음")

    # ══════════ L8 · PMTU ══════════
    # 큰 패킷이 드롭되고 ICMP Fragmentation Needed 가 오지 않으면
    # 연결은 성립하지만 큰 응답 전송이 멈춘다 (PMTU 블랙홀).
    def l8_pmtu(self, t: Target) -> None:
        if self.a.mode != "full" or not t.ips or is_sinkhole(t.ip):
            return
        ip = t.ip
        self.sect("L8 · PMTU — 큰 패킷 통과 여부")
        okmax = 0
        for size in (1472, 1452, 1420, 1400, 1300, 1200):
            self.ck()
            if ping_size(ip, size):
                okmax = size
                self.row(self.st.OK, f"{size}B", f"통과 (경로 MTU {size + 28})")
                break
            self.row(self.st.NG, f"{size}B", "막힘")
        if okmax == 0:
            self.row(self.st.IN, "판정", "모든 크기 무응답 — ICMP 차단 경로. PMTU 판정 불가")
            self.note("ICMP 차단과 큰 패킷 차단은 이 검사로 구분 불가")
        elif okmax < 1472:
            self.row(self.st.WN, "판정", f"유효 MTU {okmax + 28} — 1500 미만")
            self.rep.add(WARN, "L8",
                         f"경로 MTU {okmax + 28}. "
                         "큰 응답만 멈추는 증상과 관련될 수 있음.")

    # ══════════ L9 · 대조군 ══════════
    def l9_baseline(self) -> None:
        self.sect("L9 · 대조군 — 회선 정상 여부")
        up = tot = 0
        for spec in self.a.baseline:
            host, _, ps = spec.partition(":")
            port = int(ps) if ps.isdigit() else 443
            ip = host if is_ip_literal(host) else ""
            if not ip:
                a = resolve_system(host)
                ip = a.addrs[0] if a.addrs else ""
            if not ip:
                # 이름 해석 실패는 회선 실패로 집계하지 않는다.
                self.row(self.st.WN, f"{host}:{port}", "이름 해석 실패 — 대조군에서 제외")
                continue
            self.ck()
            r = tcp_probe(ip, port, self.a.timeout, self.proxy)
            if r.status == PROXY_DENY:
                # 프록시 정책 거부는 회선 상태와 무관 — 집계에서 제외
                self.row(self.st.WN, f"{host}:{port}", f"{ip}  프록시가 연결 거부 — 대조군에서 제외")
                continue
            tot += 1
            if r.ok:
                up += 1
                # L7b 경로 비교 기준으로 쓸 정상 대조군 IP
                self.rep.data.setdefault("baseline_ok", []).append(ip)
                self.row(self.st.OK, f"{host}:{port}", f"{ip}  {r.ms}ms")
            else:
                self.row(self.st.NG, f"{host}:{port}", f"{ip}  {WHY[r.status]}")
        self.rep.data["baseline"] = {"up": up, "total": tot}
        inet_up = self.rep.data.get("internet", {}).get("up", 0)
        if tot == 0:
            self.row(self.st.WN, "판정", "사용 가능한 대조군 없음 — 비교 없이 판정")
            self.rep.add(WARN, "L9", "대조군 없음. --baseline 값 확인 필요.")
        elif up == 0:
            # L2(IP 직접 연결)가 성공했으면 대조군 실패는 회선이 아닌 대조군 문제로 처리한다.
            if inet_up:
                self.row(self.st.WN, "판정", "대조군 전부 실패, L2 는 정상 — 회선 문제 아님")
                self.rep.add(WARN, "L9", "대조군 연결 실패, IP 직접 연결(L2)은 정상. 대조군 설정 확인 필요.")
            else:
                self.rep.add(CRIT, "L9", "대조군 연결도 전부 실패. 목적지가 아닌 로컬 회선·기기 문제.")
        elif up == tot:
            self.rep.add(INFO, "L9", f"대조군 {up}/{tot} 정상 — 회선 정상.")

    # 근본 원인 계층별 원인 구간 설명과 짧은 이름
    BLAME = {
        "L0": "로컬 기기·내부 네트워크. 공유기·케이블·Wi-Fi 점검.",
        "L1": "로컬 기기·내부 네트워크. 공유기·케이블·Wi-Fi 점검.",
        "L2": "인터넷 회선 전체. 통신사에 인터넷 연결 장애로 문의.",
        "L9": "인터넷 회선 전체. 통신사에 인터넷 연결 장애로 문의.",
        "L2b": "실패한 회선의 통신사 경로. 다른 회선으로는 같은 목적지에 연결됨.",
        "L2c": "프록시 정책·설정. 목적지 문제 아님.",
        "L3": "이름 해석(DNS). 공유기 DNS·보안 SW·사내 정책 확인. DNS 서버를 바꿔도 같으면 투명 가로채기.",
        "L3b": "도메인 자체. 오타·미등록·만료·권위 서버 장애 확인 — 네트워크 문제 아님.",
        "L4b": "경로 출처(RPKI). 광고 AS 가 대역의 정당한 소유자가 아님 — 인증서 확인 필요.",
        "L5": "TLS. 서버 인증서 문제 또는 중간 가로채기 장비.",
        "L5b": "TLS 가로채기. 이 기기·네트워크의 SSL 검사 장비·소프트웨어 확인.",
        "L6": "애플리케이션. 네트워크 정상 — 키·권한·한도·서버 오류 확인.",
        "L8": "경로 MTU. 공유기 MTU 를 1400 으로 낮춰 재현 여부 확인.",
    }
    WHO = {"L0": "로컬 기기·내부망", "L1": "로컬 기기·내부망", "L2": "인터넷 회선", "L9": "인터넷 회선",
           "L2b": "실패한 회선의 통신사", "L2c": "프록시", "L3": "DNS",
           "L3b": "도메인", "L4": "경로 또는 목적지", "L4b": "경로 출처(RPKI)",
           "L7": "경로 또는 목적지", "L5": "TLS·인증서", "L5b": "TLS 가로채기",
           "L6": "목적지 애플리케이션", "L6b": "URL 변형", "L8": "경로 MTU"}
    PATH_CODES = ("bad_addr", "no_local_v6", "local_block", "node_fail", "intercept",
                  "tcp_rst", "host_alive")

    def _path_owner(self, name: str) -> tuple[str, str, str]:
        """L4·L7 실패의 원인 구간. (짧은 이름, 설명, 조치)"""
        if self.rep.has_code("bad_addr", target=name):
            return ("입력 주소·포트", "입력한 주소·포트 오류. 네트워크 문제 아님.",
                    "DNS 응답 또는 설정 파일의 주소·포트 확인")
        if self.rep.has_code("no_local_v6", target=name):
            return ("로컬 IPv6 미지원", "로컬 회선·기기에 IPv6 경로 없음. 목적지 문제 아님.",
                    "IPv4 주소로 검사하거나 IPv6 지원 회선에서 재검사")
        if self.rep.has_code("local_block", target=name):
            return ("로컬 방화벽·보안 SW", "이 기기의 방화벽·보안 소프트웨어가 연결 차단. 네트워크 문제 아님.",
                    "방화벽·보안 SW·콘텐츠 필터 설정 확인")
        if self.rep.has_code("node_fail", target=name):
            return ("특정 서버(노드)",
                    "시스템 DNS 가 준 서버 IP 만 실패. 같은 서비스의 다른 IP 는 연결됨 — 해당 노드 장애 또는 IP 단위 차단.",
                    "DNS 캐시를 비운 뒤 재검사, 계속되면 목적지에 해당 IP 장애 문의")
        if self.rep.has_code("intercept", target=name):
            return ("중간 장비(투명 프록시)",
                    "중간 장비. 경로상 장비가 목적지 대신 응답.",
                    "TLS 인증서 발급자로 장비 확인")
        if self.rep.has_code("tcp_rst", target=name):
            return ("목적지 서버", "목적지 서버. 패킷은 도착, 서버가 RST 로 거절 — 서비스 미동작 또는 포트 닫힘.", "")
        if self.rep.has_code("host_alive", target=name):
            return ("목적지 포트 정책",
                    "목적지 서버의 포트 정책. 경로는 정상, 해당 포트만 차단.",
                    '목적지 관리자에게: "해당 포트가 우리 공인 IP 에서 연결되지 않음. 허용목록 확인 요청"')
        return ("경로 또는 목적지", "경로 구간 또는 목적지 방화벽(DROP). 로컬 기기 문제 아님.", "")

    def headline(self, name: str, t: Optional[Target] = None) -> str:
        """대상별 결론 한 줄."""
        crit = self.rep.crit_layers(name)
        if not crit:
            if self.errors_for(name):
                return "일부 검사 중단 — 결과 불완전"
            if t is not None and t.ips and not t.tcp_ok:
                return "치명적 실패 없음, 연결은 실패"
            warns = [f for f in self.rep.scope(name) if f.level == WARN]
            return ("문제 없음 — 경고 있음" if warns else "문제 없음 — 전 계층 통과")
        root = crit[0]
        who = self.who(name)
        first = next(f.message for f in self.rep.scope(name)
                     if f.level == CRIT and f.layer == root)
        return f"{root} · {who} — {trunc(first, 58)}"

    def errors_for(self, name: str) -> int:
        """그 대상(및 공통 검사)에서 예외로 중단된 계층 수."""
        return self.errors_by.get("", 0) + (self.errors_by.get(name, 0) if name else 0)

    def who(self, name: str) -> str:
        """근본 원인 계층의 원인 구간 짧은 이름. CRIT 가 없으면 빈 문자열."""
        crit = self.rep.crit_layers(name)
        if not crit:
            return ""
        root = crit[0]
        if root == "L0" and self.rep.has_code("proxy_down", target=name):
            return "프록시 연결 불가"
        if root == "L0" and self.rep.has_code("no_local_v6", target=name):
            return "로컬 IPv6 미지원"
        if root == "L3" and self.rep.has_code("hosts_block", target=name):
            return "hosts 파일"
        if root == "L6" and self.rep.has_code("http_timeout", target=name):
            return "HTTP 응답 없음"
        return self._path_owner(name)[0] if root in ("L4", "L7") else self.WHO.get(root, root)

    def _names(self, targets: list[Target]) -> list[str]:
        """판정 대상 이름. 입력 오류로 Target 이 만들어지지 않은 대상도 포함한다."""
        names = [t.key for t in targets]
        for f in self.rep.findings:
            if f.target and f.target not in names:
                names.append(f.target)
        return names

    def summary_line(self, targets: list[Target]) -> None:
        if self.a.json:
            return
        by = {t.key: t for t in targets}
        names = self._names(targets)
        print(f"\n{self.st.B}요약{self.st.RST}")
        for name in names:
            mark = (self.st.NG if self.rep.crit_layers(name)
                    else (self.st.WN if self.errors_for(name) else self.st.OK))
            label = f"{pad(trunc(name, 24), 25)} " if len(names) > 1 else ""
            print(f"  {mark} {label}{self.headline(name, by.get(name))}")

    # ══════════ 판정 ══════════
    # 발견 사항을 대상별로 묶어 출력하고 원인 구간·조치를 붙인다.
    # 공통 검사(target "")는 대상이 여럿이면 한 번만 출력한다.
    def verdict(self, targets: list[Target]) -> int:
        self.sect("판정 — 원인 계층·구간")
        names = self._names(targets) or [""]
        multi = len(names) > 1
        marks = {CRIT: self.st.NG, WARN: self.st.WN, INFO: self.st.IN}

        def show(fs: list[Finding]) -> None:
            for lv in (CRIT, WARN, INFO):
                for f in fs:
                    if f.level == lv and not self.a.json:
                        print(f"  {marks[lv]} {pad(f.layer, 4)} {f.message}")

        if multi:
            env = [f for f in self.rep.findings if f.target == ""]
            if env:
                show(env)
        for name in names:
            mine = ([f for f in self.rep.findings if f.target == name] if multi
                    else self.rep.scope(name))
            if multi and not self.a.json:
                print(f"\n  {self.st.B}{name}{self.st.RST}")
            show(mine)
            if not self.a.json:
                print()
            self._blame(name)
        self.summary_line(targets)

        if any(f.level == CRIT for f in self.rep.findings):
            return 1
        return 3 if self.internal_errors else 0

    def blame_of(self, name: str) -> tuple[str, list[str]]:
        """(원인 구간 설명, 조치 목록)."""
        crits = self.rep.crit_layers(name)
        if not crits:
            n = self.errors_for(name)
            if n:
                return (f"치명적 실패 없음. {n}개 계층이 예외로 중단 — 진단 불완전.", [])
            return ("치명적 실패 없음. 위 경고 사항만 확인.", [])
        root = crits[0]
        if root in ("L4", "L7"):
            _who, text, hint = self._path_owner(name)
            if hint:
                return (text, [hint])
            hints = []
            if not self.rep.has_code(*self.PATH_CODES, target=name):
                last = self.rep.data.get("last_hop", {}).get(name)
                dest = self.rep.data.get("dest_ip", {}).get(name)
                if last and dest:
                    hints.append(f'통신사 문의: "{last} 이후 {dest} 방향 도달 불가"')
                hints.append("다른 회선(휴대폰 테더링)으로 재검사 — 연결되면 통신사 경로 문제,")
                hints.append("연결 안 되면 목적지 네트워크 장애. 회선이 2개 이상이면 L2b 에서 자동 비교.")
            return (text, hints)
        if root == "L0" and self.rep.has_code("proxy_down", target=name):
            return ("프록시 연결 불가. 프록시 주소·포트·실행 상태 확인.", [])
        if root == "L3" and self.rep.has_code("hosts_block", target=name):
            return ("hosts 파일·로컬 해석 설정. 이 기기의 hosts 파일 또는 차단 소프트웨어 확인.",
                    ["macOS·Linux: /etc/hosts, Windows: C:\\Windows\\System32\\drivers\\etc\\hosts"])
        if root == "L0" and self.rep.has_code("no_local_v6", target=name):
            return ("로컬 회선·기기에 IPv6 경로 없음. 목적지 문제 아님.",
                    ["-6 없이 검사하거나 IPv6 지원 회선에서 재검사"])
        if root == "L6" and self.rep.has_code("http_timeout", target=name):
            return ("HTTP 응답 없음. TCP 연결은 성공 — 서버 미응답 또는 중간 장비의 HTTP 차단.",
                    ["같은 URL 을 브라우저·curl 로 확인", "다른 회선에서 재검사 — 연결되면 경로상 장비의 차단"])
        hints = {"L3b": ["철자 확인, whois 로 등록 상태 확인"],
                 "L2c": ["프록시 거부 사유를 관리자에게 전달"]}.get(root, [])
        return (self.BLAME.get(root, "확인 필요"), hints)

    def _blame(self, name: str) -> None:
        text, hints = self.blame_of(name)
        self.rep.data.setdefault("blame", {})[name] = {"text": text, "hints": hints}
        self.row(f"{self.st.B}{self.st.g('→')}{self.st.RST}", "원인 구간", text)
        for h in hints:
            self.note(h)


# ═══════════════════════ 시스템 정보 ═══════════════════════

def win_default_route() -> tuple[str, str]:
    """`route print -4` 에서 기본 경로를 읽는다.
    머리글은 번역되므로 `0.0.0.0  0.0.0.0  <게이트웨이>  <로컬 주소>  <메트릭>` 숫자 행만 쓴다."""
    best, gw = None, ""
    for line in run_cmd(["route", "print", "-4"]).splitlines():
        f = line.split()
        if len(f) >= 5 and f[0] == "0.0.0.0" and f[1] == "0.0.0.0":
            try:
                metric = int(f[4])
            except ValueError:
                continue
            if is_ip_literal(f[2]) and (best is None or metric < best):
                best, gw = metric, f[2]
    return gw, "기본 인터페이스"


def default_route() -> tuple[str, str]:
    try:
        if IS_WIN:
            return win_default_route()
        if IS_MAC:
            out = subprocess.run(["route", "-n", "get", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            gw = pick(out, r"gateway:\s*(\S+)")
            ifc = pick(out, r"interface:\s*(\S+)")
        else:
            out = subprocess.run(["ip", "route", "show", "default"],
                                 capture_output=True, text=True, timeout=5).stdout
            gw = pick(out, r"default via (\S+)")
            ifc = pick(out, r"dev (\S+)")
        return gw, ifc
    except (OSError, subprocess.TimeoutExpired):
        return "", ""


def win_mtu() -> Optional[int]:
    """`netsh interface ipv4 show subinterfaces` 의 숫자 열에서 MTU 를 읽는다.
    머리글은 번역되므로 각 행의 첫 숫자(MTU)만 쓴다."""
    vals = []
    for line in run_cmd(["netsh", "interface", "ipv4", "show", "subinterfaces"]).splitlines():
        f = line.split()
        if len(f) >= 5 and f[0].isdigit():
            n = int(f[0])
            if 576 <= n <= 65535:
                vals.append(n)
    if not vals:
        return None
    # 루프백(4294967295 등)은 위에서 제외. 9216 이하 값 중 최댓값.
    return max(v for v in vals if v <= 9216) if any(v <= 9216 for v in vals) else None


def iface_info(iface: str) -> tuple[str, Optional[int]]:
    if IS_WIN:
        return local_ip_for(), win_mtu()
    if not iface:
        return "", None
    try:
        if shutil.which("ifconfig"):
            out = subprocess.run(["ifconfig", iface], capture_output=True,
                                 text=True, timeout=5).stdout
            addr = pick(out, r"inet (\d+\.\d+\.\d+\.\d+)")
            mtu = pick(out, r"mtu (\d+)")
        else:
            out = subprocess.run(["ip", "addr", "show", iface], capture_output=True,
                                 text=True, timeout=5).stdout
            addr = pick(out, r"inet (\d+\.\d+\.\d+\.\d+)")
            mtu = pick(out, r"mtu (\d+)")
        return addr, int(mtu) if mtu else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "", None


def default_route_ifaces() -> set[str]:
    """기본 경로를 가진 인터페이스. Windows 는 인터페이스 주소, 그 외는 인터페이스 이름."""
    found: set[str] = set()
    try:
        if IS_WIN:
            for line in run_cmd(["route", "print", "-4"]).splitlines():
                f = line.split()
                if len(f) >= 5 and f[0] == "0.0.0.0" and f[1] == "0.0.0.0" and is_ip_literal(f[3]):
                    found.add(f[3])
        elif IS_MAC:
            txt = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True,
                                 text=True, timeout=5).stdout
            for line in txt.splitlines():
                f = line.split()
                if len(f) >= 4 and f[0] == "default":
                    found.add(f[3])
        else:
            txt = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True,
                                 text=True, timeout=5).stdout
            found.update(re.findall(r"\bdev (\S+)", txt))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return found


def usable_interfaces() -> list[tuple[str, str]]:
    """회선 대조(L2b)에 쓸 (인터페이스, 주소). 자체 기본 경로가 있는 인터페이스만 포함한다
    (가상·호스트 전용·VPN 어댑터는 출발지를 고정해도 외부로 나가지 못해 거짓 실패가 됨)."""
    routed = default_route_ifaces()
    if not routed:
        return []
    return [(ifc, ip) for ifc, ip in _all_interfaces()
            if (ip if IS_WIN else ifc) in routed]


def _all_interfaces() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if IS_WIN:
        # 인터페이스 이름은 번역·사용자 지정 값이므로 주소로 구분한다.
        try:
            _h, _a, ips = socket.gethostbyname_ex(socket.gethostname())
        except OSError:
            ips = []
        me = local_ip_for()
        for ip in dict.fromkeys(list(ips) + ([me] if me else [])):
            if ip and not ip.startswith(("127.", "169.254.")):
                out.append((f"주소 {ip}", ip))
        return out
    try:
        if shutil.which("ifconfig"):
            txt = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
            cur = ""
            for line in txt.splitlines():
                if line and not line[0].isspace():
                    cur = line.split(":")[0]
                m = re.search(r"\binet (\d+\.\d+\.\d+\.\d+)", line)
                if m and cur and not m.group(1).startswith(("127.", "169.254.")):
                    out.append((cur, m.group(1)))
        else:
            txt = subprocess.run(["ip", "-o", "-4", "addr"], capture_output=True,
                                 text=True, timeout=5).stdout
            for line in txt.splitlines():
                p = line.split()
                if len(p) > 3 and not p[3].startswith(("127.", "169.254.")):
                    out.append((p[1], p[3].split("/")[0]))
    except (OSError, subprocess.TimeoutExpired):
        pass
    return out


def route_dev(dst: str, src: str) -> str:
    try:
        out = subprocess.run(["ip", "route", "get", dst, "from", src],
                             capture_output=True, text=True, timeout=5).stdout
        return pick(out, r"\bdev (\S+)")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def tunnels() -> list[str]:
    names: list[str] = []
    if IS_WIN:
        return []          # 인터페이스 이름으로 터널 여부를 판단할 수 없음
    try:
        if shutil.which("ifconfig"):
            txt = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5).stdout
            names = re.findall(r"^((?:utun|tun|tap|ppp|ipsec|wg)\d+):", txt, re.M)
        else:
            txt = subprocess.run(["ip", "-o", "link"], capture_output=True,
                                 text=True, timeout=5).stdout
            names = re.findall(r"\d+: ((?:utun|tun|tap|ppp|ipsec|wg)\d+):", txt)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return names


def win_proxy() -> tuple[str, str]:
    """(표시용 문자열, 프록시 URL). 레지스트리에서 읽는다."""
    try:
        import winreg
        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            def q(name):
                try:
                    return winreg.QueryValueEx(k, name)[0]
                except OSError:
                    return None
            on = q("ProxyEnable")
            server = str(q("ProxyServer") or "")
            pac = str(q("AutoConfigURL") or "")
    except Exception:
        return "", ""
    parts, url = [], ""
    if on and server:
        parts.append(server)
        # 형식: "http=host:80;https=host:443" 또는 "host:port"
        if "=" in server:
            for chunk in server.split(";"):
                if chunk.startswith(("https=", "http=")):
                    url = "http://" + chunk.split("=", 1)[1]
                    break
        else:
            url = "http://" + server
    if pac:
        parts.append("PAC " + pac)
    return " ".join(parts), url


def system_proxy() -> str:
    if IS_WIN:
        return win_proxy()[0]
    if not IS_MAC:
        return ""
    try:
        out = subprocess.run(["scutil", "--proxy"], capture_output=True,
                             text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    on = []
    for kind, host_k, port_k in (("HTTP", "HTTPProxy", "HTTPPort"),
                                 ("HTTPS", "HTTPSProxy", "HTTPSPort"),
                                 ("SOCKS", "SOCKSProxy", "SOCKSPort")):
        if re.search(rf"{kind}Enable\s*:\s*1", out):
            h = pick(out, rf"{host_k}\s*:\s*(\S+)")
            p = pick(out, rf"{port_k}\s*:\s*(\d+)")
            on.append(f"{kind.lower()}://{h}:{p}" if h else kind)
    if re.search(r"ProxyAutoConfigEnable\s*:\s*1", out):
        on.append("PAC " + pick(out, r"ProxyAutoConfigURLString\s*:\s*(\S+)"))
    return " ".join(on)


def proxy_from_system() -> Optional[Proxy]:
    """시스템·환경변수 프록시 설정을 읽는다 (앱과 같은 경로로 검사)."""
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY",
              "all_proxy", "ALL_PROXY"):
        v = os.environ.get(k)
        if v:
            return Proxy.parse(v)
    if IS_WIN:
        url = win_proxy()[1]
        if url:
            try:
                return Proxy.parse(url)
            except ValueError:
                return None
        return None
    if IS_MAC:
        try:
            out = subprocess.run(["scutil", "--proxy"], capture_output=True,
                                 text=True, timeout=5).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        for kind, hk, pk, scheme in (("HTTPS", "HTTPSProxy", "HTTPSPort", "http"),
                                     ("HTTP", "HTTPProxy", "HTTPPort", "http"),
                                     ("SOCKS", "SOCKSProxy", "SOCKSPort", "socks5")):
            if re.search(rf"{kind}Enable\s*:\s*1", out):
                h = pick(out, rf"{hk}\s*:\s*(\S+)")
                p = pick(out, rf"{pk}\s*:\s*(\d+)")
                if h and p:
                    return Proxy(scheme, h, int(p))
    return None


def pick(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.I | re.M)
    return m.group(1).strip() if m else ""


# 2단계 공개 접미사 (whois·NS·CT 조회 대상 도메인 산출용)
TWO_LEVEL = re.compile(
    r"^(co|ne|or|go|re|pe|ac|hs|ms|es|kg|sc)\.kr$"
    r"|^(co|ne|or|go|ac|ad|ed|gr|lg)\.jp$"
    r"|^(com|net|org|gov|edu|ac|co)\.(uk|au|nz|za|in|br|cn|tw|hk|sg|my|mx|ar|tr|ua|ph|vn|id|th|il|pk|ng|eg|sa)$")


def registrable(host: str) -> str:
    parts = host.rstrip(".").split(".")
    if len(parts) < 2:
        return host
    two = ".".join(parts[-2:])
    if TWO_LEVEL.match(two) and len(parts) >= 3:
        return ".".join(parts[-3:])
    return two


def whois_domain(dom: str, timeout: float = 8.0) -> str:
    tld = dom.rsplit(".", 1)[-1]
    ref = whois_raw(dom, f"{tld}.whois-servers.net", timeout)
    if not ref.strip():
        ref = whois_raw(dom, "whois.iana.org", timeout)
    srv = pick(ref, r"(?:Registrar WHOIS Server|refer|whois)\s*:\s*(\S+)")
    if srv and srv not in dom:
        deep = whois_raw(dom, srv, timeout)
        if len(deep) > len(ref):
            return ref + "\n" + deep
    return ref


# ═══════════════════ 보고서 ═══════════════════
# Markdown 보고서. 통신사·목적지 담당자에게 전달할 수 있도록 측정 시각·위치·근거를 담는다.

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def write_report(path: str, nc: "Netcheck", targets: list[Target],
                 a: argparse.Namespace, raw: str = "",
                 watch: Optional[list[str]] = None) -> bool:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_report(nc, targets, a, raw, watch))
        return True
    except OSError as ex:
        print(f"보고서 저장 실패: {ex}", file=sys.stderr)
        return False


def render_report(nc: "Netcheck", targets: list[Target],
                  a: argparse.Namespace, raw: str = "",
                  watch: Optional[list[str]] = None) -> str:
    p = nc.rep.data
    L: list[str] = []
    L.append("# 네트워크 도달성 진단 결과")
    L.append("")
    L.append(f"- 시각: {time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    L.append(f"- 도구: netcheck {VERSION} ({platform.system()} {platform.release()})")
    L.append(f"- 측정 위치: 로컬 주소 `{p.get('address') or '?'}`, "
             f"게이트웨이 `{p.get('gateway') or '?'}`")
    if p.get("public_ip"):
        L.append(f"- **공인 IP: `{p['public_ip']}`** (문의 시 이 주소 전달)")
    L.append(f"- DNS 서버: `{', '.join(system_resolvers()) or '?'}`")
    if a.proxy_obj:
        L.append(f"- 프록시 경유: `{a.proxy_obj.label}`")
    L.append(f"- 설정: 반복 {a.repeat}회, 타임아웃 {a.timeout}초, 범위 {a.mode}")
    L.append("")

    names = nc._names(targets)
    by = {t.key: t for t in targets}
    L.append("## 결론")
    L.append("")
    for name in names:
        crit = nc.rep.crit_layers(name)
        L.append(f"- **{name}** — {'❌' if crit else '✅'} {nc.headline(name, by.get(name))}")
    L.append("")
    env = [f for f in nc.rep.findings if f.target == "" and f.level in (CRIT, WARN)]
    if env:
        L.append("공통 항목(회선·기기):")
        for f in env:
            L.append(f"- [{f.layer}] {f.message}")
        L.append("")

    L.append("## 측정 근거")
    L.append("")
    L.append(f"- 인터넷 연결(IP 직접): "
             f"{p.get('internet', {}).get('up', 0)}/{p.get('internet', {}).get('tried', 0)} 성공")
    L.append(f"- 대조군: "
             f"{p.get('baseline', {}).get('up', 0)}/{p.get('baseline', {}).get('total', 0)} 성공")
    L.append("")
    for name in names:
        t = by.get(name)
        L.append(f"### {name}" + (f":{t.port}{t.path if t.path != '/' else ''}" if t else ""))
        L.append("")
        mine = [f for f in nc.rep.findings if f.target == name]
        for lv, tag in ((CRIT, "**치명**"), (WARN, "경고")):
            for f in mine:
                if f.level == lv:
                    L.append(f"- {tag} [{f.layer}] {f.message}")
        if mine:
            L.append("")
        if not t:
            continue
        rows = [("해석된 주소", f"`{', '.join(t.ips) or '없음'}`")]
        if t.truth and set(t.truth) != set(t.ips):
            rows.append(("DoH 응답", f"`{', '.join(t.truth)}` (시스템 응답과 다름)"))
        rows.append((f"TCP {t.port}", "성공" if t.tcp_ok else "**실패**"))
        if t.v6_ok is not None:
            rows.append(("IPv6", f"`{t.ips6[0]}` " + ("성공" if t.v6_ok else "**실패**")))
        if t.mss:
            rows.append(("MSS", f"{t.mss}" + ("" if t.mss >= 1440 else " (1500 미만 경로)")))
        if t.ttl_dist:
            rows.append(("TCP 홉 거리", f"{t.ttl_dist}홉"))
        if t.meta and t.meta.routed:
            rows.append(("목적지 소유자",
                         f"AS{t.meta.asn} {t.meta.short_name} ({t.meta.prefix}, {t.meta.cc})"))
        if t.rpki:
            rows.append(("경로 출처(RPKI)", t.rpki))
        ap = p.get("as_path", {}).get(t.key)
        if ap:
            rows.append(("경로(AS 단위)", ap))
        last = p.get("last_hop", {}).get(t.key)
        if last and not t.tcp_ok:
            rows.append(("**마지막 응답 홉**", f"`{last}` — 다음 구간에서 중단"))
        L.append("| 항목 | 값 |")
        L.append("|---|---|")
        for k, v in rows:
            L.append(f"| {k} | {v} |")
        variants = p.get("variants", {}).get(t.key) or []
        if variants:
            L.append("")
            L.append("| URL 변형 | 결과 |")
            L.append("|---|---|")
            for v in variants:
                mark = "✅" if v["works"] else "❌"
                L.append(f"| `{v['url']}`{' (입력)' if v['input'] else ''} | {mark} {v['text']} |")
        hops = p.get("hops", {}).get(t.key) or []
        if hops:
            L.append("")
            L.append("```")
            L.append(f"{'홉':>3}  {'주소':<16} {'RTT':>8} {'응답':>6}  소유자")
            for h in hops:
                if not h.ips:
                    L.append(f"{h.n:>3}  {'*':<16} {'-':>8} {f'{h.recv}/{h.sent}':>6}  무응답")
                    continue
                mt = h.meta
                own = f"AS{mt.asn} {mt.short_name}" if mt and mt.routed else ip_class(h.ip)
                rt = f"{h.rtt:.2f}" if h.rtt is not None else "-"
                L.append(f"{h.n:>3}  {h.ip:<16} {rt:>8} {f'{h.recv}/{h.sent}':>6}  {own}")
            L.append("```")
        L.append("")

    if watch:
        L.append("## 반복 관측 (--watch)")
        L.append("")
        L.append("```")
        L.extend(watch)
        L.append("```")
        L.append("")
        L.append("위 측정 근거는 마지막 회차 결과.")
        L.append("")

    L.append("## 결과 활용")
    L.append("")
    L.append("- `[L4]`·`[L7]`: 경로 문제. **마지막 응답 홉과 목적지 주소**를 통신사에 전달.")
    L.append("- `[L6]`: 네트워크 정상. 목적지 서비스 담당자에게 문의.")
    L.append("- `[L3]`·`[L3b]`: 이름(DNS·도메인) 문제.")
    L.append("- 간헐 장애: `--watch` 로 반복 측정한 요약을 함께 전달.")
    if raw:
        L.append("")
        L.append("<details><summary>전체 진단 출력</summary>")
        L.append("")
        L.append("```")
        L.append(ANSI_RE.sub("", raw).rstrip())
        L.append("```")
        L.append("</details>")
    L.append("")
    return "\n".join(L)


# ═══════════════════ 반복 관측 ═══════════════════
# 반복 관측 (--watch). 결론이 바뀐 회차만 상세 출력하고 나머지는 한 줄로 표시한다.

@dataclass
class Snapshot:
    at: float
    rc: int
    roots: dict[str, Optional[str]]        # 대상 → 근본 원인 계층
    findings: dict[str, list[str]]         # 대상 → CRIT 메시지

    def key(self) -> str:
        """결론 비교용 키. 측정값이 아닌 판정 결과만 포함한다."""
        return json.dumps({k: (self.roots.get(k), sorted(self.findings.get(k, [])))
                           for k in sorted(self.roots)}, ensure_ascii=False)


def snapshot(nc: "Netcheck", targets: list[Target]) -> Snapshot:
    roots, finds = {}, {}
    for name in nc._names(targets):
        crit = nc.rep.crit_layers(name)
        roots[name] = crit[0] if crit else None
        # 측정값(IP 등)이 들어간 문구 대신 계층·분류만 비교 (GSLB IP 교체로 '결론 변경' 오판 방지)
        finds[name] = sorted({f"{f.layer}:{f.code}" for f in nc.rep.scope(name) if f.level == CRIT})
    return Snapshot(time.time(), exit_code(nc), roots, finds)


def watch_loop(a: argparse.Namespace) -> int:
    st = Style(a.color, getattr(a, "unicode_ok", True))
    hist: list[Snapshot] = []
    prev_key = None
    worst = 0
    n = 0
    last: Optional[tuple["Netcheck", list[Target], str]] = None
    print(f"{st.B}반복 관측{st.RST} — {a.watch}초 간격"
          + (f", {a.count}회" if a.count else ", Ctrl+C 로 중지") + "\n")
    try:
        while True:
            n += 1
            # 2회차부터는 출력을 버퍼에만 담고 결론이 바뀐 경우에 출력한다.
            buf = io.StringIO()
            out = buf if prev_key is not None else Tee(sys.stdout, buf)
            with contextlib.redirect_stdout(out):
                nc, targets = run_diagnosis(a)
                nc.verdict(targets)
                nc.pool.shutdown(wait=False)
            text = buf.getvalue()
            last = (nc, targets, text)
            snap = snapshot(nc, targets)
            hist.append(snap)
            # 치명적 실패(1)를 내부 오류(3)보다 우선
            worst = 1 if 1 in (worst, snap.rc) else max(worst, snap.rc)
            stamp = time.strftime("%H:%M:%S", time.localtime(snap.at))
            summary = ", ".join(
                f"{h}={r or '정상'}" for h, r in snap.roots.items()) or "대상 없음"
            if prev_key is not None and snap.key() != prev_key:
                print(f"\n{st.WNC}{'─' * 60}{st.RST}")
                print(f"{st.B}[{stamp}] 결론 변경{st.RST} — {summary}\n")
                print(text.rstrip())
            elif prev_key is not None:
                mark = st.OK if snap.rc == 0 else (st.NG if snap.rc == 1 else st.WN)
                print(f"  {mark} [{stamp}] {n:3d}회  {summary}")
            else:
                # 1회차는 전체 출력을 이미 표시함
                print(f"\n  {st.DIM}[{stamp}] 1회 — 기준 결과. "
                      f"이후에는 결론이 바뀔 때만 상세 출력{st.RST}")
            prev_key = snap.key()
            if a.count and n >= a.count:
                break
            time.sleep(max(1, a.watch))
    except KeyboardInterrupt:
        print("\n중단")
    lines = watch_summary(hist, st)
    if a.report and last:
        nc, targets, text = last
        if write_report(a.report, nc, targets, a, text, lines):
            print(f"\n보고서 저장: {a.report}")
    return worst


def watch_summary(hist: list[Snapshot], st: Style) -> list[str]:
    """반복 관측 요약을 출력하고 보고서용 평문 줄을 돌려준다. 상시 실패와 간헐 실패를 구분한다."""
    if not hist:
        return []
    plain: list[str] = []

    def out(mark: str, text: str, note: str = "") -> None:
        print(f"  {mark} {text}")
        plain.append(f"{mark} {text}")
        if note:
            print(f"      {st.DIM}{note}{st.RST}")
            plain.append(f"    {note}")

    print(f"\n{st.B}반복 관측 결과 — {len(hist)}회{st.RST}")
    span = hist[-1].at - hist[0].at
    out(st.IN, f"{pad('기간', 20)} {time.strftime('%H:%M:%S', time.localtime(hist[0].at))}"
               f" ~ {time.strftime('%H:%M:%S', time.localtime(hist[-1].at))}"
               f"  ({int(span // 60)}분 {int(span % 60)}초, {len(hist)}회)")
    for h in hist[0].roots:
        bad = [s for s in hist if s.roots.get(h)]
        if not bad:
            out(st.OK, f"{pad(h, 20)} {len(hist)}회 모두 정상")
            continue
        layers = "/".join(sorted({s.roots[h] for s in bad if s.roots[h]}))
        first = time.strftime("%H:%M:%S", time.localtime(bad[0].at))
        last = time.strftime("%H:%M:%S", time.localtime(bad[-1].at))
        if len(bad) == len(hist):
            out(st.NG, f"{pad(h, 20)} {len(bad)}/{len(hist)}회 실패 — 상시 실패 ({layers})",
                "전 회차 실패 — 상시 장애")
        else:
            out(st.WN, f"{pad(h, 20)} {len(bad)}/{len(hist)}회 실패 — 간헐 실패 "
                       f"({layers}), 처음 {first} 마지막 {last}",
                "일부 회차만 실패 — 부하·경로 변동·일부 노드 불량 확인")
    changes = sum(1 for i in range(1, len(hist)) if hist[i].key() != hist[i - 1].key())
    if changes:
        out(st.IN, f"{pad('결론 변경', 20)} {changes}회 — 위 상세 출력 참조")
    return [ANSI_RE.sub("", ln) for ln in plain]


# ═══════════════════════ 진입점 ═══════════════════════

EPILOG = """\
검사 계층
  L0  로컬 환경(주소·공인 IP·NAT·VPN·프록시)   L1  게이트웨이
  L2  인터넷 연결(DNS 없이)  L2b 회선 대조   L2c 프록시 대조
  L3  DNS(DoH 대조)         L3b 도메인·권위 서버
  L4  TCP(실패 유형 · IPv4/IPv6 · MSS · TCP 홉 거리)
  L4b 목적지 정보(소유자·abuse 연락처·RPKI)
  L5  TLS(인증서·SNI)       L5b 인증서 이력(CT 로그)
  L6  HTTP(리다이렉트·중간 경유)  L6b URL 변형(https·http × www)
  L7  경로(AS·손실·PTR·역방향)  L7b 정상 대조군과 경로 비교
  L8  PMTU                 L9  대조군

결과 읽기
  가장 얕은 계층의 실패를 근본 원인으로 판정한다. 결론은 마지막 [판정] 절에 출력.

프록시
  --proxy http://host:3128          HTTP 프록시 경유 검사
  --proxy socks5h://127.0.0.1:1080  이름 해석도 프록시에서 수행
  --proxy-system                    시스템·환경변수 프록시 설정 사용
  프록시 지정 시 L2c 에서 직접 연결과 프록시 연결을 비교한다.

반복 관측 · 보고서
  --watch 초     지정 간격으로 반복. 결론이 바뀐 회차만 상세 출력,
                 종료 시 상시 실패/간헐 실패 요약
  --count N      --watch 반복 횟수 (생략 시 Ctrl+C 까지)
  --report 파일  Markdown 보고서 저장 — 공인 IP, 마지막 응답 홉, 경로 표 포함
                 (--watch 와 함께 쓰면 마지막 회차 결과 + 반복 관측 요약)

요약 출력
  netcheck.py -b 대상          결론과 조치만 출력
  URL 입력 시 해당 경로까지 HTTP 로 확인

예시
  netcheck.py https://apis.data.go.kr/openapi/service   # URL
  netcheck.py -b apis.data.go.kr                        # 결론만
  netcheck.py apis.data.go.kr
  netcheck.py apis.data.go.kr www.weather.go.kr    # 여러 대상 비교
  netcheck.py --watch 60 --count 30 flaky.example  # 30분간 반복 관측
  netcheck.py --report 장애.md apis.data.go.kr     # 보고서 저장
  netcheck.py --proxy http://proxy.corp:3128 api.example.com
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="netcheck.py",
        description=f"netcheck v{VERSION} — 계층별 도달성 진단",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("targets", nargs="+", metavar="대상",
                   help="호스트 · 호스트:포트 · URL (https://a.com/v1/x 형식 가능)")
    p.add_argument("-p", "--port", type=int, default=443, help="기본 포트 (443)")
    p.add_argument("-t", "--timeout", type=float, default=4.0, help="연결 타임아웃 초 (4)")
    p.add_argument("-r", "--repeat", type=int, default=3, help="TCP 반복 횟수 (3)")
    p.add_argument("-i", "--interval", type=float, default=0.0, help="반복 사이 간격 초 (0)")
    p.add_argument("-m", "--max-hop", type=int, default=20, help="traceroute 최대 홉 (20)")
    p.add_argument("-4", dest="ipv", action="store_const", const=4, help="IPv4 강제")
    p.add_argument("-6", dest="ipv", action="store_const", const=6, help="IPv6 강제")
    p.add_argument("-q", "--quick", action="store_true", help="경로·목적지 정보·도메인 검사 생략")
    p.add_argument("-f", "--full", action="store_true", help="전체 검사 (포트 스캔·PMTU·CT 포함)")
    p.add_argument("--no-trace", action="store_true", help="traceroute 만 생략")
    p.add_argument("--baseline", default="1.1.1.1:443,8.8.8.8:443,www.google.com:443",
                   help="대조군 (쉼표 구분)")
    p.add_argument("--ct", action="store_true",
                   help="CT 로그(crt.sh)로 인증서 이력 확인 (-f 에 포함)")
    p.add_argument("--no-ct", action="store_true", help="-f 에서도 CT 조회 생략")
    p.add_argument("--no-variants", action="store_true",
                   help="URL 변형(https·http·www 조합) 확인 생략")
    p.add_argument("--proxy", metavar="URL", help="프록시 경유 검사")
    p.add_argument("--proxy-system", action="store_true", help="시스템 프록시 설정 사용")
    p.add_argument("--watch", type=int, metavar="초",
                   help="지정 간격(초)으로 반복 관측 (결론이 바뀐 회차만 상세 출력)")
    p.add_argument("--count", type=int, metavar="N", help="--watch 반복 횟수")
    p.add_argument("--report", metavar="파일",
                   help="Markdown 보고서 저장")
    p.add_argument("-b", "--brief", action="store_true",
                   help="결론과 조치만 출력")
    p.add_argument("--json", action="store_true", help="JSON 출력")
    p.add_argument("--no-color", action="store_true", help="색 출력 끔")
    a = p.parse_args(argv)

    if any(not t.strip() for t in a.targets):
        p.error("빈 대상이 포함됨")
    a.targets = list(dict.fromkeys(t.strip() for t in a.targets))     # 완전히 같은 대상 중복 제거
    if a.watch and a.json:
        p.error("--watch 와 --json 은 함께 사용 불가")
    if a.watch is not None and a.watch < 1:
        p.error("--watch 는 1초 이상")
    if a.count is not None and a.count < 1:
        p.error("--count 는 1 이상")
    if a.repeat < 1:
        p.error("반복 횟수는 1 이상")
    if a.timeout <= 0:
        p.error("타임아웃은 0 보다 커야 함")
    if a.max_hop < 1:
        p.error("홉 수는 1 이상")
    if not (1 <= a.port <= 65535):
        p.error(f"포트 범위(1~65535) 초과: {a.port}")

    a.mode = "full" if a.full else ("quick" if a.quick else "normal")
    a.trace = not (a.no_trace or a.quick)
    a.probes = 3 if a.full else 2
    a.ct = (a.ct or a.full) and not a.no_ct
    a.variants = not a.no_variants
    a.ipv = a.ipv or 0
    a.unicode_ok = setup_stdout()
    a.color = (sys.stdout.isatty() and not a.no_color and not a.json
               and enable_ansi())
    a.baseline = [s.strip() for s in a.baseline.split(",") if s.strip()]
    if not a.baseline:
        p.error("--baseline 값 필요")

    a.proxy_obj = None
    if a.proxy:
        try:
            a.proxy_obj = Proxy.parse(a.proxy)
        except ValueError as ex:
            p.error(str(ex))
    elif a.proxy_system:
        a.proxy_obj = proxy_from_system()
        if a.proxy_obj is None:
            p.error("시스템 프록시 설정 없음")
    return a


def url_variants(host: str, path: str = "/") -> list[tuple[str, str]]:
    """(스킴, 호스트) 조합. www 는 등록 도메인 자체이거나 www. 로 시작할 때만 붙이거나 뗀다."""
    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    elif registrable(host) == host:
        hosts.append("www." + host)
    return [(sch, h) for sch in ("https", "http") for h in hosts]


def split_target(spec: str, default_port: int) -> tuple[str, int, str, str, str]:
    """(호스트, 포트, 오류, 경로, 스킴). URL 입력 시 경로·스킴도 추출해 L5·L6 에서 사용한다.

    스킴 없는 입력: host · host:port · [IPv6]:port · IPv6 · host/path · host?query"""
    spec = spec.strip()
    if re.match(r"^https?://", spec, re.I):
        u = urlsplit(spec)
        sc = u.scheme.lower()
        try:
            port = u.port
        except ValueError:
            return "", 0, f"포트 지정 오류: '{spec}'", "/", sc
        host = u.hostname or ""            # userinfo 제거·소문자·대괄호 제거
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if not host:
            return "", 0, f"호스트 없음: '{spec}'", path, sc
        return host, port or (443 if sc == "https" else 80), "", path, sc
    if "://" in spec:
        return "", 0, f"지원하지 않는 스킴: '{spec.split('://')[0]}'", "/", ""

    # 경로·질의 분리 (IPv6 주소에는 / ? # 가 없음)
    m = re.match(r"^([^/?#]*)(.*)$", spec)
    hostport, rest = m.group(1), m.group(2)
    path = "/"
    if rest:
        path = (rest if rest.startswith("/") else "/" + rest).split("#", 1)[0] or "/"
    m = re.match(r"^\[(?P<h>[0-9a-fA-F:.]+)\](?::(?P<p>.*))?$", hostport)
    if m:
        ps = m.group("p")
        if ps is not None and not ps.isdigit():
            return "", 0, f"포트가 숫자가 아님: '{ps}'", path, ""
        return m.group("h"), int(ps or default_port), "", path, ""
    if hostport.count(":") > 1:                     # 포트 없는 IPv6 리터럴
        return hostport, default_port, "", path, ""
    host, sep, ps = hostport.partition(":")
    if sep and not ps.isdigit():
        return "", 0, f"포트가 숫자가 아님: '{ps}'", path, ""
    return host, (int(ps) if ps else default_port), "", path, ""

def run_diagnosis(a: argparse.Namespace,
                  sink: Optional[Callable[[str, dict], None]] = None,
                  abort: Optional[Callable[[], None]] = None
                  ) -> tuple["Netcheck", list[Target]]:
    """진단을 실행하고 (Netcheck, 대상 목록) 을 돌려준다. CLI·GUI 공용."""
    nc = Netcheck(a)
    nc.sink = sink
    nc.abort_check = abort
    nc.emit("meta", version=VERSION, mode=a.mode,
            proxy=(a.proxy_obj.label if a.proxy_obj else None),
            targets=list(a.targets), baseline=list(a.baseline),
            repeat=a.repeat, timeout=a.timeout, ct=a.ct, trace=a.trace)
    if not a.json:
        print(f"{nc.st.B}netcheck v{VERSION}{nc.st.RST}  "
              f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {a.mode}모드"
              + (f"  프록시 {a.proxy_obj.label}" if a.proxy_obj else ""))
        print(f"{nc.st.DIM}대상: {' '.join(a.targets)}   "
              f"대조군: {' '.join(a.baseline)}{nc.st.RST}")

    global ABORT
    ABORT = abort
    try:
        nc.safe("L0", nc.l0_local)
        nc.safe("L1", nc.l1_link)
        nc.safe("L2", nc.l2_internet)
        nc.safe("L9", nc.l9_baseline)

        parsed = []
        for spec in a.targets:
            host, port, err, path, scheme = split_target(spec, a.port)
            if not err and host:
                host, err = normalize_host(host)
            parsed.append((spec, host, port, err, path, scheme))
        hosts = [h for _s, h, _p, e, _pa, _sc in parsed if h and not e]
        used: set[str] = set()

        targets: list[Target] = []
        for spec, host, port, err, path, scheme in parsed:
            # 같은 호스트가 여러 번이면 host:port 로 구분
            key = host or spec
            if host and hosts.count(host) > 1:
                key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            base, n = key, 2
            while key in used:
                key, n = f"{base}#{n}", n + 1
            used.add(key)
            nc.ck()
            nc.rep.cur = key
            # 입력 오류 대상은 port 0 (화면에서 입력값 그대로 표시)
            nc.emit("target", key=key, host=host or spec, port=0 if (err or not host) else port)
            if not a.json:
                shown = (f"[{host}]:{port}" if ":" in host else f"{host}:{port}") if host else trunc(spec, 40)
                sep = nc.st.g("═")
                bar = sep * max(2, 46 - width(shown))
                print(f"\n{nc.st.B}{sep * 2} {shown} {bar}{nc.st.RST}")
            if err or not host:
                msg = err or f"호스트 없음: '{spec}'"
                nc.row(nc.st.NG, "대상", f"{msg}  ('{trunc(spec, 40)}')")
                nc.rep.add(CRIT, "L4", f"대상 지정 오류 — {msg} ('{trunc(spec, 40)}')", "bad_addr")
                continue
            if not (1 <= port <= 65535):
                nc.row(nc.st.NG, "포트", f"{port} — 포트 범위(1~65535) 초과")
                nc.rep.add(CRIT, "L4", f"{host} 포트 지정 오류: {port}", "bad_addr")
                continue
            t = Target(host, port, key)
            t.path, t.scheme = path, scheme
            targets.append(t)
            if not nc.safe("L3", nc.l3_dns, t, default=False):
                nc.safe("L6b", nc.l6b_variants, t)     # 이름이 실패해도 www 등 변형은 확인
                continue
            nc.safe("L3b", nc.l3b_domain, t)
            nc.safe("L2b", nc.l2b_multipath, t)
            nc.safe("L2c", nc.l2c_proxy, t)
            if nc.safe("L4", nc.l4_tcp, t, default=False):
                nc.safe("L4b", nc.l4b_identity, t)
                tls = nc.safe("L5", nc.l5_tls, t)
                nc.safe("L5b", nc.l5b_ct, t, tls)
                nc.safe("L6", nc.l6_http, t)
            else:
                nc.safe("L4b", nc.l4b_identity, t)
            nc.safe("L6b", nc.l6b_variants, t)
            nc.safe("L7", nc.l7_path, t)
            nc.safe("L7b", nc.l7b_diff, t)
            nc.safe("L8", nc.l8_pmtu, t)
        nc.rep.cur = ""
        return nc, targets
    except BaseException:
        shutdown_pool(nc.pool)
        raise
    finally:
        ABORT = None


def shutdown_pool(pool: futures.ThreadPoolExecutor) -> None:
    """대기 중 작업을 취소하고 스레드 풀을 정리한다 (실행 중 작업은 기다리지 않음)."""
    try:
        pool.shutdown(wait=False, cancel_futures=True)       # 3.9+
    except TypeError:
        pool.shutdown(wait=False)


def to_payload(nc: "Netcheck", targets: list[Target],
               a: argparse.Namespace) -> dict:
    def target_doc(t: Target) -> dict:
        m = t.meta
        crit = nc.rep.crit_layers(t.key)
        cause, actions = nc.blame_of(t.key)
        return {
            "key": t.key, "host": t.host, "port": t.port, "path": t.path,
            "root_layer": crit[0] if crit else None,
            "summary": nc.headline(t.key, t),
            "who": nc.who(t.key) or None,
            "cause": cause, "actions": actions,
            "ips": t.ips, "ips6": t.ips6, "truth": t.truth,
            "tcp_ok": t.tcp_ok, "ipv6_ok": t.v6_ok,
            "mss": t.mss, "tcp_hops": t.ttl_dist,
            "asn": m.asn if m else None,
            "as_name": m.as_name if m else None,
            "bgp_prefix": m.prefix if m else None,
            "country": m.cc if m else None,
            "registry": m.registry if m else None,
            "allocated": m.allocated if m else None,
            "ptr": m.ptr if m else None,
            "kind": ip_kind(m) if m else None,
            "rpki": t.rpki or None,
            "as_path": nc.rep.data.get("as_path", {}).get(t.key),
            "variants": nc.rep.data.get("variants", {}).get(t.key),
            "last_hop": nc.rep.data.get("last_hop", {}).get(t.key),
        }

    return {
        "version": VERSION,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": a.mode,
        "proxy": a.proxy_obj.label if a.proxy_obj else None,
        "local": {k: nc.rep.data.get(k) for k in
                  ("gateway", "interface", "address", "public_ip", "mtu")},
        "resolvers": system_resolvers(),
        "internet": nc.rep.data.get("internet", {}),
        "baseline": nc.rep.data.get("baseline", {}),
        "targets": [target_doc(t) for t in targets],
        "invalid_targets": [
            {"host": name, "root_layer": (nc.rep.crit_layers(name) or [None])[0],
             "summary": nc.headline(name), "who": nc.who(name) or None,
             "cause": nc.blame_of(name)[0], "actions": nc.blame_of(name)[1]}
            for name in nc._names(targets) if name not in {t.key for t in targets}],
        "findings": [asdict(f) for f in nc.rep.findings],
        "internal_errors": nc.internal_errors,
    }


def exit_code(nc: "Netcheck") -> int:
    if any(f.level == CRIT for f in nc.rep.findings):
        return 1
    return 3 if nc.internal_errors else 0


def main(argv: list[str]) -> int:
    a = parse_args(argv)
    if a.watch:
        return watch_loop(a)

    if a.brief and not a.json:
        # 계층별 출력은 버퍼에 담고 결론만 출력한다.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            nc, targets = run_diagnosis(a)
            rc = nc.verdict(targets)
        print_brief(nc, targets)
        if a.report and write_report(a.report, nc, targets, a, buf.getvalue()):
            print(f"보고서 저장: {a.report}")
        nc.pool.shutdown(wait=False)
        return rc

    # 보고서에 화면 출력 전문을 포함하기 위해 출력을 함께 저장한다.
    cap = io.StringIO() if a.report and not a.json else None
    if cap is not None:
        with contextlib.redirect_stdout(Tee(sys.stdout, cap)):
            nc, targets = run_diagnosis(a)
            rc = nc.verdict(targets)
    else:
        nc, targets = run_diagnosis(a)
        rc = exit_code(nc) if a.json else nc.verdict(targets)
        if a.json:
            print(json.dumps(to_payload(nc, targets, a), ensure_ascii=False, indent=2))
    try:
        if a.report and write_report(a.report, nc, targets, a, cap.getvalue() if cap else ""):
            # --json 이면 stdout 은 JSON 전용
            print(f"\n보고서 저장: {a.report}", file=sys.stderr if a.json else sys.stdout)
        return rc
    finally:
        nc.pool.shutdown(wait=False)


def print_brief(nc: "Netcheck", targets: list[Target]) -> None:
    """대상별 발견 사항·원인 구간·조치만 출력한다."""
    st = nc.st
    by = {t.key: t for t in targets}
    names = nc._names(targets)
    for name in names:
        print(f"{st.B}{name}{st.RST}")
        for f in nc.rep.scope(name):
            if f.level in (CRIT, WARN):
                print(f"  {st.NG if f.level == CRIT else st.WN} [{f.layer}] {f.message}")
        text, hints = nc.blame_of(name)
        print(f"\n  {st.g('→')} 원인 구간  {text}")
        for h in hints:
            print(f"      {h}")
        print()
    print(f"{st.B}요약{st.RST}")
    for name in names:
        mark = st.NG if nc.rep.crit_layers(name) else st.OK
        label = f"{pad(trunc(name, 24), 25)} " if len(names) > 1 else ""
        print(f"  {mark} {label}{nc.headline(name, by.get(name))}")


class Tee(io.TextIOBase):
    """여러 스트림에 동시에 쓴다 (화면 출력 + 보고서용 저장)."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)
        return len(s)

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n중단됨", file=sys.stderr)
        sys.exit(130)
