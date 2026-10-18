#!/usr/bin/env python3
"""판정 검증 — 가상 네트워크 상황에서 판정 결과를 확인한다.

근본 원인 계층·결론 문구·종료 코드를 검사한다. 실제 네트워크를 쓰지 않는다.

    python3 tools/test_verdicts.py            # 전체
    python3 tools/test_verdicts.py 싱크홀      # 이름에 해당 문자열이 포함된 시나리오만
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import contextlib
from dataclasses import dataclass, field
from typing import Any, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("netcheck", os.path.join(HERE, "netcheck.py"))
N = importlib.util.module_from_spec(spec)
sys.modules["netcheck"] = N
spec.loader.exec_module(N)


# stub 과 실제 함수의 시그니처가 다르면 진단이 '내부 오류' 로 빠진다.
# 교체 전 실제 시그니처를 저장해 두고 비교한다.
import inspect

_REAL_TCP_PROBE = N.tcp_probe          # stub 교체 전 실제 함수 (errno 분류 시험용)
_REAL_SIGS = {name: inspect.signature(getattr(N, name))
              for name in ("tcp_probe", "tcp_series", "tls_probe", "http_probe",
                           "traceroute", "ping", "ping_size", "dns_query",
                           "doh_query", "cymru_bulk", "ct_lookup", "rir_lookup",
                           "ptr_lookup", "resolve_system", "tcp_ttl_distance", "os_resolve")}


def check_stub_signatures() -> list[str]:
    """stub 이 실제 함수와 같은 인자로 호출 가능한지 확인한다 (install 후 비교)."""
    install(World())
    errs = []
    for name, real in _REAL_SIGS.items():
        stub = getattr(N, name)
        try:
            sig = inspect.signature(stub)
        except (TypeError, ValueError):
            continue
        need = [p for p in real.parameters.values()
                if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
        have = {p.name for p in sig.parameters.values()}
        if any(p.kind == p.VAR_KEYWORD for p in sig.parameters.values()):
            continue
        missing = [p.name for p in need if p.name not in have]
        if missing:
            errs.append(f"{name}() stub 에 없는 인자: {', '.join(missing)}  "
                        f"(실제: {real})")
    return errs


# ─────────────────────── 가상 네트워크 ───────────────────────

def A(*ips, rcode="NOERROR", ttl=300, cnames=()):
    return N.DnsAnswer(rcode, list(ips), list(cnames), [], ttl, 3)


def meta(ip, asn="64500", name="TEST-AS - Example Net, KR", prefix="93.184.216.0/24",
         cc="KR", reg="apnic", alloc="2010-01-01"):
    return N.IpMeta(ip, asn, prefix, cc, reg, alloc, name)


def hop(n, ip, rtt=5.0, recv=2, sent=2):
    return N.Hop(n, [ip] if ip else [], rtt, recv, sent)


OKCERT = dict(ok=True, verified=True, version="TLSv1.3", cipher="X", alpn="h2",
              subject="commonName=example.com", issuer="O=Let's Encrypt, CN=R11",
              not_after="Dec 31 23:59:59 2030 GMT", days_left=900,
              sans=["example.com"], name_match=True, serial="AA", not_before="")


@dataclass
class World:
    """가상 네트워크 동작 정의. 시나리오에 필요한 값만 채운다."""
    sys_dns: dict = field(default_factory=dict)      # 이름 → DnsAnswer (시스템)
    pub_dns: dict = field(default_factory=dict)      # 이름 → DnsAnswer (공용 53)
    doh: dict = field(default_factory=dict)          # 이름 → DnsAnswer (DoH)
    tcp: dict = field(default_factory=dict)          # (ip,port) → TcpResult
    tcp_default: Any = None
    tls: Optional[dict] = None
    http: Optional[dict] = None
    hops: list = field(default_factory=list)
    hop_meta: dict = field(default_factory=dict)
    trace_mode: str = "UDP"
    ping_ret: tuple = (0.0, 3.0, 58)
    ct: Optional[Any] = None
    ifaces: list = field(default_factory=lambda: [("en0", "10.0.0.2")])
    proxy_deny: str = ""                              # 프록시 거부 사유
    proxy_deny_ip: bool = False                       # 프록시가 IP 주소 CONNECT 만 거부
    all_down: bool = False                            # 대조군 포함 전체 불통
    whois_down: bool = False                          # whois 조회 실패
    v6: dict = field(default_factory=dict)            # 이름 → AAAA DnsAnswer
    mss: Optional[int] = None                         # 협상된 MSS
    rpki: tuple = ("valid", "")                       # RPKI 검증 결과
    ttl_dist: Optional[int] = None                    # TCP 홉 거리
    whois_dom: str = ""
    os_dns: dict = field(default_factory=dict)        # 이름 → OS 해석기 결과 (hosts 등)
    http_by: dict = field(default_factory=dict)       # (스킴, 호스트) → HttpInfo 값 (URL 변형 시험)
    local_v6: bool = True                             # 로컬 IPv6 경로 존재 여부

    # L2·L9 대조군 주소. all_down 이 아니면 항상 연결되도록 한다.
    CONTROL = {"1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222", "142.250.1.1"}

    def result(self, ip, port, proxy=None):
        if (ip, port) in self.tcp:
            return self.tcp[(ip, port)]
        if ip in World.CONTROL and not self.all_down and not (proxy is not None and self.proxy_deny_ip):
            return N.TcpResult(N.OPEN, 5)
        if proxy is not None and self.proxy_deny:
            return N.TcpResult(N.PROXY_DENY, 5, self.proxy_deny)
        if proxy is not None and self.proxy_deny_ip and N.is_ip_literal(ip):
            return N.TcpResult(N.PROXY_DENY, 5, "CONNECT 거부 403 IP not allowed")
        if self.tcp_default is not None:
            return self.tcp_default
        return N.TcpResult(N.OPEN, 5)


def install(w: World) -> None:
    """netcheck 모듈의 네트워크 함수를 가상 네트워크 stub 으로 교체한다."""
    DEFAULT_NAMES = {"www.google.com": A("142.250.1.1")}

    def _sys(name, want6=False):
        if want6:
            return w.v6.get(name, N.DnsAnswer("NOERROR", []))
        if name in w.sys_dns:
            return w.sys_dns[name]
        return DEFAULT_NAMES.get(name, A())
    N.resolve_system = _sys

    def _os(host, want6=False):
        if host in w.os_dns:
            return w.os_dns[host]
        return _sys(host, want6).addrs
    N.os_resolve = _os
    N.dns_query = lambda name, qtype, server, timeout=2.0: (
        w.pub_dns.get(name) or w.sys_dns.get(name) or A())
    N.doh_query = lambda name, qtype, timeout, proxy=None: w.doh.get(name)
    N.tcp_probe = (lambda host, port, timeout, proxy=None, source_ip=None:
                   w.result(host, port, proxy))

    def series(host, port, timeout, tries, interval=0.0, proxy=None,
               source_ip=None, abort=None):
        r = w.result(host, port, proxy)
        if r.ok:
            return N.TcpSeries(tries, tries, [r.ms] * tries, None)
        return N.TcpSeries(tries, 0, [], r)
    N.tcp_series = series

    N.tls_probe = lambda host, ip, port, timeout, proxy=None, sni=True: (
        N.TlsInfo(**(w.tls if w.tls is not None else OKCERT)))
    def _http(host, ip, port, timeout, scheme, proxy=None, max_redirects=5, path="/"):
        spec = w.http_by.get((scheme, host))
        if spec is None:
            spec = w.http if w.http is not None else dict(
                ok=True, code=200, version="1.1", size=10, chain=[N.HttpStep(200)],
                t_connect=5, t_tls=10, t_ttfb=20, t_total=25)
        return N.HttpInfo(**spec)
    N.http_probe = _http
    N.traceroute = lambda ip, max_hops, probes, timeout: (w.hops, w.trace_mode)
    N.ping = lambda target, count=5: w.ping_ret
    N.ping_size = lambda ip, payload: True
    N.tcp_ttl_distance = lambda ip, port, timeout=2.0, max_ttl=32: w.ttl_dist
    N.tcp_mss = lambda ip, port, timeout=4.0, proxy=None: w.mss
    N.rpki_validate = lambda asn, prefix, timeout, proxy=None: w.rpki
    N.ripe_netinfo = lambda ip, timeout=12.0, proxy=None: None
    def _cymru(ips, timeout=10.0):
        if w.whois_down:
            return N.MetaSet(ok=False)      # 조회 실패
        return N.MetaSet({i: w.hop_meta.get(i, meta(i))
                          for i in ips if not N.is_private(i)})
    N.cymru_bulk = _cymru
    N.rir_lookup = lambda ip, registry, timeout=8.0: {"netname": "TESTNET", "org": "Example"}
    N.ptr_lookup = lambda ip, timeout=2.0: ""
    N.ct_lookup = lambda domain, serial, timeout, proxy=None: (
        w.ct if w.ct is not None else N.CtInfo(reachable=False, error="시험 중"))
    N.whois_domain = lambda dom, timeout=8.0: w.whois_dom
    N.default_route = lambda: ("10.0.0.1", "en0")
    N.iface_info = lambda iface: ("10.0.0.2", 1500)
    N.system_resolvers = lambda: ["10.0.0.1"]
    N.usable_interfaces = lambda: w.ifaces
    N.tunnels = lambda: []
    N.system_proxy = lambda: ""
    N.proxy_from_system = lambda: None
    N.https_get = lambda h, ip, p, t, hd=None, px=None: (200, b"ip=93.184.216.9\n")
    N.local_ip_for = lambda dst="1.1.1.1": (
        "" if ":" in dst and not w.local_v6 else ("2001:db8::99" if ":" in dst else "10.0.0.2"))


def diagnose(w: World, argv: list[str]) -> tuple[int, list, str]:
    install(w)
    a = N.parse_args(["--no-color"] + argv)
    a.color = False
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        nc, targets = N.run_diagnosis(a)
        rc = nc.verdict(targets)
        nc.pool.shutdown(wait=False)
    return rc, nc.rep.findings, buf.getvalue()


# ─────────────────────── 시나리오 ───────────────────────
# 각 항목: (이름, 가상 네트워크, 인자, 기대 근본 원인 계층, 포함돼야 할 문구, 없어야 할 문구)

BASE = ["-q", "--no-trace", "-r", "1"]
# L4b(목적지 정보·RPKI)는 -q 에서 생략되므로 별도 인자를 쓴다.
IDENT = ["--no-trace", "-r", "1"]
FULL = ["-m", "8", "-r", "1"]

CASES: list[tuple] = []


def case(name, world, argv, root, must, must_not=()):
    """must 는 전체 출력+발견 사항에서, must_not 은 원인 구간 줄+발견 사항에서만 찾는다."""
    CASES.append((name, world, argv, root, must, must_not))


# ── 정상 ──
case("정상",
     World(sys_dns={"ok.example": A("93.184.216.10")},
           doh={"ok.example": A("93.184.216.10")}),
     BASE + ["ok.example"], None, ["치명적 실패 없음"], ["차단", "조작"])

# ── L3 이름 계열 ──
case("싱크홀 — DoH IP 로는 연결됨",
     World(sys_dns={"blk.example": A("0.0.0.0")},
           doh={"blk.example": A("93.184.216.20")},
           tcp={("93.184.216.20", 443): N.TcpResult(N.OPEN, 7)}),
     BASE + ["blk.example"], "L3",
     ["DNS 만 차단됨", "대상 서버는 정상"])

case("NXDOMAIN — 존재하지 않는 이름",
     World(sys_dns={"nope.example": A(rcode="NXDOMAIN")},
           doh={"nope.example": A(rcode="NXDOMAIN")}),
     BASE + ["nope.example"], "L3b",
     ["이름 없음"], ["가로채기"])

case("NODATA — 시스템 DNS·DoH 모두 주소 레코드 없음",
     World(sys_dns={"nd.example": A()}, doh={"nd.example": A()}),
     BASE + ["nd.example"], "L3b",
     ["NODATA"], ["가로채기", "보안 SW"])

case("NXDOMAIN 주입 — 시스템 DNS 만 NXDOMAIN",
     World(sys_dns={"inj.example": A(rcode="NXDOMAIN")},
           doh={"inj.example": A("93.184.216.30")}),
     BASE + ["inj.example"], "L3",
     ["NXDOMAIN", "차단"])

case("CDN/GSLB — 응답 IP 가 달라도 같은 AS 면 정상",
     World(sys_dns={"cdn.example": A("93.184.216.40")},
           doh={"cdn.example": A("93.184.216.41")},
           hop_meta={"93.184.216.40": meta("93.184.216.40", "13335"),
                     "93.184.216.41": meta("93.184.216.41", "13335")}),
     BASE + ["cdn.example"], None, [], ["조작"])

case("DNS 조작 — 다른 AS 의 IP 로 응답",
     World(sys_dns={"hij.example": A("45.33.32.5")},
           doh={"hij.example": A("93.184.216.50")},
           pub_dns={"hij.example": A("45.33.32.5")},
           hop_meta={"45.33.32.5": meta("45.33.32.5", "64999"),
                     "93.184.216.50": meta("93.184.216.50", "13335")},
           # 조작된 IP 는 그 이름의 인증서를 제공하지 못함
           tls=dict(OKCERT, verified=False, error="hostname mismatch", name_match=False)),
     BASE + ["hij.example"], "L3",
     ["조작", "투명 가로채기"])

case("whois 조회 실패 + IP 다름 + 인증서 정상 — 조작으로 판정하지 않음",
     World(sys_dns={"gw.example": A("93.184.216.51")}, doh={"gw.example": A("93.184.216.52")},
           whois_down=True),
     BASE + ["gw.example"], None, ["인증서가 gw.example 로 검증됨"], ["조작"])

case("whois 조회 실패 + IP 다름 + 인증서 검증 실패 — 판정 보류(경고)",
     World(sys_dns={"gw2.example": A("93.184.216.53")}, doh={"gw2.example": A("93.184.216.54")},
           whois_down=True, tls=dict(OKCERT, verified=False, error="x", name_match=False)),
     BASE + ["--no-trace", "gw2.example"], "L5", ["판정 불가"], ["DNS 응답 조작"])

case("다른 AS 지만 인증서 정상 — ISP 내 캐시",
     World(sys_dns={"isp.example": A("93.184.216.55")}, doh={"isp.example": A("93.184.216.56")},
           hop_meta={"93.184.216.55": meta("93.184.216.55", "64500"),
                     "93.184.216.56": meta("93.184.216.56", "15169")}),
     BASE + ["isp.example"], None, ["ISP 내 캐시"], ["조작"])

case("hosts 파일 차단 — OS 해석기 결과 사용",
     World(sys_dns={"ad.example": A("93.184.216.57")}, doh={"ad.example": A("93.184.216.57")},
           os_dns={"ad.example": ["0.0.0.0"]}),
     BASE + ["ad.example"], "L3", ["hosts 파일"], ["공유기"])

case("분할 DNS — 직접 질의는 NXDOMAIN, OS 해석기는 응답",
     World(sys_dns={"intra.example": A(rcode="NXDOMAIN")}, doh={"intra.example": A(rcode="NXDOMAIN")},
           os_dns={"intra.example": ["10.1.2.3"]}),
     BASE + ["intra.example"], None, ["OS 해석기"], ["이름 없음"])

case("IPv6 전용 이름 + 로컬 IPv6 없음 — 도메인 문제 아님",
     World(sys_dns={"v6only.example": A()}, doh={"v6only.example": A()},
           v6={"v6only.example": A("2001:db8::6")}, local_v6=False),
     BASE + ["v6only.example"], "L4", ["IPv6 전용 이름", "로컬 IPv6 미지원"], ["NODATA", "도메인"])

case("IPv6 전용 이름 + 로컬 IPv6 있음 — IPv6 로 검사",
     World(sys_dns={"v6ok.example": A()}, doh={"v6ok.example": A()},
           v6={"v6ok.example": A("2001:db8::7")}),
     BASE + ["v6ok.example"], None, ["IPv6 전용 이름"], ["NODATA"])

case("시스템 DNS 만 SERVFAIL — 로컬 DNS 문제 (L3)",
     World(sys_dns={"sf.example": A(rcode="SERVFAIL")}, doh={"sf.example": A("93.184.216.58")},
           pub_dns={"sf.example": A("93.184.216.58")}),
     BASE + ["sf.example"], "L3", ["시스템 DNS 서버만 SERVFAIL"], ["도메인 측"])

case("NXDOMAIN + DoH 차단 + 공용 DNS 응답 — NXDOMAIN 주입 (L3)",
     World(sys_dns={"nx2.example": A(rcode="NXDOMAIN")},
           pub_dns={"nx2.example": A("93.184.216.59")}),
     BASE + ["nx2.example"], "L3", ["NXDOMAIN", "공용 DNS 결과"], ["오타"])

case("53번 가로채기 — 공용 DNS 질의에 필터 CNAME",
     World(sys_dns={"ss.example": A("93.184.216.60", cnames=["forcesafesearch.example"])},
           pub_dns={"ss.example": A("93.184.216.60", cnames=["forcesafesearch.example"])},
           doh={"ss.example": A("93.184.216.60")}),
     BASE + ["ss.example"], None, ["평문 DNS(53) 가로채기"], [])

# ── L4 연결 계열 ──
case("포트 차단 — 다른 포트는 연결됨",
     World(sys_dns={"p.example": A("93.184.216.60")},
           doh={"p.example": A("93.184.216.60")},
           tcp={("93.184.216.60", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.60", 80): N.TcpResult(N.OPEN, 6),
                ("93.184.216.60", 22): N.TcpResult(N.REFUSED, 3)}),
     BASE + ["p.example"], "L4",
     ["포트 정책", "허용목록"])

case("포트 차단 — 대상 포트 DROP, 다른 포트 RST",
     World(sys_dns={"pr.example": A("93.184.216.65")},
           doh={"pr.example": A("93.184.216.65")},
           tcp={("93.184.216.65", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.65", 80): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.65", 22): N.TcpResult(N.REFUSED, 3)}),
     BASE + ["pr.example"], "L4",
     ["포트 정책", "호스트 동작 중"], ["경로 구간"])

case("서비스 중지 — RST",
     World(sys_dns={"r.example": A("93.184.216.70")},
           doh={"r.example": A("93.184.216.70")},
           tcp_default=N.TcpResult(N.REFUSED, 3, "ECONNREFUSED")),
     BASE + ["r.example"], "L4",
     ["서버가 RST 로 거절", "서비스 미동작"])

case("예약 대역 — 주소 오류",
     World(sys_dns={"doc.example": A("192.0.2.77")},
           doh={"doc.example": A("192.0.2.77")},
           tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response")),
     BASE + ["doc.example"], "L4",
     ["주소", "문서용"], ["통신사"])

case("BGP 미광고 주소",
     World(sys_dns={"na.example": A("93.184.216.90")},
           doh={"na.example": A("93.184.216.90")},
           hop_meta={"93.184.216.90": meta("93.184.216.90", "NA", "NA")},
           tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response")),
     BASE + ["na.example"], "L4",
     ["BGP 미광고"], ["통신사"])

case("whois 조회 실패 — BGP 미광고로 판정하지 않음",
     World(sys_dns={"w.example": A("93.184.216.95")},
           doh={"w.example": A("93.184.216.95")},
           whois_down=True,
           tcp_default=N.TcpResult(N.OPEN, 5)),
     BASE + ["w.example"], None, [], ["BGP 미광고"])

# ── L7 경로 계열 ──
case("ISP 내부 구간에서 중단 — 중간 홉 손실은 경로 손실로 판정하지 않음",
     # 경로가 목적지에 도달하지 않았으므로 마지막 응답 홉의 손실로 경로 손실을 판정하지 않는다.
     World(sys_dns={"far.example": A("93.184.216.100")},
           doh={"far.example": A("93.184.216.100")},
           tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response"),
           hops=[hop(1, "10.0.0.1"), hop(2, "100.64.1.1", 5.0, 1, 2),
                 hop(3, None, None, 0, 2)],
           hop_meta={"93.184.216.100": meta("93.184.216.100", "64500")}),
     FULL + ["far.example"], "L4",
     ["통신사", "사설 대역"], ["목적지까지 패킷 손실"])

case("최대 홉 도달 — 중단 지점으로 판정하지 않음",
     World(sys_dns={"mh.example": A("93.184.216.105")},
           doh={"mh.example": A("93.184.216.105")},
           tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response"),
           hops=[hop(i, f"100.64.1.{i}") for i in range(1, 9)]),
     FULL + ["mh.example"], "L4",
     ["최대 홉(8) 도달"], ["이후 중단", "사설 대역", "목적지 네트워크 내부"])

case("ICMP 만 차단 — TCP 는 도달",
     World(sys_dns={"icmp.example": A("93.184.216.110")},
           doh={"icmp.example": A("93.184.216.110")},
           hops=[hop(1, "10.0.0.1"), hop(2, "198.51.100.9"), hop(3, None, None, 0, 2)]),
     FULL + ["icmp.example"], None,
     ["ICMP/UDP 필터링"], ["이후 중단", "경로 구간"])

# ── L5 TLS ──
case("인증서 만료",
     World(sys_dns={"exp.example": A("93.184.216.120")},
           doh={"exp.example": A("93.184.216.120")},
           tls=dict(OKCERT, verified=False, error="certificate has expired",
                    days_left=-30, not_after="Jan 01 00:00:00 2020 GMT")),
     BASE + ["exp.example"], "L5",
     ["만료"])

case("TLS 가로채기 — CT 이력에 없는 발급자",
     World(sys_dns={"mitm.example": A("93.184.216.130")},
           doh={"mitm.example": A("93.184.216.130")},
           tls=dict(OKCERT, issuer="O=Acme Corp, CN=Acme TLS Inspection CA",
                    subject="commonName=mitm.example", serial="BB"),
           ct=N.CtInfo(reachable=True, hist_ok=True, serial_found=False,
                       history=[{"not_before": "2020-01-01", "issuer_name": "CN=R11"}],
                       issuers=["R11"], names=["mitm.example"])),
     BASE + ["--ct", "mitm.example"], "L5b",
     ["TLS 가로채기(중간 재서명) 의심"])

case("CT 색인 지연 — 공개 CA 면 경고하지 않음",
     # 발급자가 이 도메인 이력에는 없지만 주요 공개 CA 인 경우.
     World(sys_dns={"new.example": A("93.184.216.140")},
           doh={"new.example": A("93.184.216.140")},
           tls=dict(OKCERT, issuer="C=GB, O=Sectigo Limited, CN=Sectigo Public DV",
                    serial="CC"),
           ct=N.CtInfo(reachable=True, hist_ok=True, serial_found=False,
                       history=[{"not_before": "2026-01-01", "issuer_name": "CN=R11"}],
                       issuers=["R11"], names=["new.example"])),
     BASE + ["--ct", "new.example"], None, [], ["가로채기", "이력에 없는 발급자"])

# ── L6 애플리케이션 ──
case("HTTP 400 + 거절 본문 — 네트워크 정상",
     World(sys_dns={"api.example": A("93.184.216.150")},
           doh={"api.example": A("93.184.216.150")},
           http=dict(ok=True, code=400, version="1.1", size=100,
                     chain=[N.HttpStep(400)], t_connect=5, t_tls=10, t_ttfb=20,
                     t_total=25, body_head="<errMsg>SERVICE_KEY_IS_NOT_REGISTERED</errMsg>")),
     BASE + ["api.example"], "L6",
     ["애플리케이션", "네트워크 정상"], ["통신사", "경로 구간"])

case("리다이렉트 대상 싱크홀 — DNS 차단 (L3)",
     World(sys_dns={"rd.example": A("93.184.216.155")},
           doh={"rd.example": A("93.184.216.155")},
           http=dict(ok=True, code=301, version="1.1", size=0,
                     chain=[N.HttpStep(301, "https://blocked.example/")], t_connect=5,
                     t_tls=10, t_ttfb=20, t_total=25,
                     redirect_error="이동 대상 blocked.example 이 0.0.0.0 로 해석됨 — 싱크홀 주소",
                     redirect_sinkhole=True)),
     BASE + ["rd.example"], "L3",
     ["DNS 에서 차단"], ["서버 오류", "애플리케이션"])

case("HTTP 응답 없이 연결 종료 — 성공으로 판정하지 않음",
     World(sys_dns={"cl.example": A("93.184.216.61")}, doh={"cl.example": A("93.184.216.61")},
           http=dict(ok=True, code=0, version="", size=0, chain=[], t_connect=5,
                     t_tls=10, t_ttfb=0, t_total=20)),
     BASE + ["cl.example"], "L6", ["HTTP 응답 없음"], ["전 계층 통과"])

case("200 페이지의 reCAPTCHA 스크립트 — 거절로 판정하지 않음",
     World(sys_dns={"rc.example": A("93.184.216.62")}, doh={"rc.example": A("93.184.216.62")},
           http=dict(ok=True, code=200, version="1.1", size=100, chain=[N.HttpStep(200)],
                     t_connect=5, t_tls=10, t_ttfb=20, t_total=25,
                     body_head='<html><head><script src="https://www.google.com/recaptcha/api.js">'
                               'var unauthorizedHandler=1;</script></head><body>로그인</body></html>')),
     BASE + ["rc.example"], None, [], ["거절"])

case("HTTP 429 — 한도 초과",
     World(sys_dns={"lim.example": A("93.184.216.160")},
           doh={"lim.example": A("93.184.216.160")},
           http=dict(ok=True, code=429, version="1.1", size=10,
                     chain=[N.HttpStep(429)], t_connect=5, t_tls=10, t_ttfb=20,
                     t_total=25, body_head="rate limit exceeded")),
     BASE + ["lim.example"], "L6", ["한도"])

# ── L6b URL 변형 ──
FAIL_HTTP = dict(ok=False, error="timed out", timed_out=True)
case("URL 변형 — 도메인 자체는 주소 없음, www 는 응답",
     World(sys_dns={"apex.example": A(), "www.apex.example": A("93.184.216.80")},
           doh={"apex.example": A()}),
     IDENT + ["apex.example"], "L3b",
     ["www.apex.example 는 응답(200)", "www 유무"], [])

case("URL 변형 — HTTPS 실패, HTTP 응답",
     World(sys_dns={"plain.example": A("93.184.216.81")}, doh={"plain.example": A("93.184.216.81")},
           http_by={("https", "plain.example"): FAIL_HTTP,
                    ("https", "www.plain.example"): FAIL_HTTP}),
     IDENT + ["plain.example"], "L6",
     ["http://plain.example 는 응답(200)", "HTTPS(443) 미지원"], [])

case("URL 변형 — 모두 정상이면 경고 없음",
     World(sys_dns={"fine.example": A("93.184.216.82"), "www.fine.example": A("93.184.216.82")},
           doh={"fine.example": A("93.184.216.82")}),
     IDENT + ["fine.example"], None, ["URL 변형"], ["는 실패"])

case("URL 변형 — --no-variants 면 생략",
     World(sys_dns={"nv.example": A("93.184.216.83")}, doh={"nv.example": A("93.184.216.83")}),
     IDENT + ["--no-variants", "nv.example"], None, [], ["URL 변형"])

# ── 대조군·회선 ──
case("회선 전체 불통 — 대조군도 실패",
     World(sys_dns={"any.example": A("93.184.216.170")},
           doh={"any.example": A("93.184.216.170")},
           all_down=True,
           tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response")),
     BASE + ["any.example"], "L2",
     ["회선"])

case("대조군 실패, L2 정상 — 회선 문제 아님",
     World(sys_dns={"y.example": A("93.184.216.185"),
                    "base.example": A("93.184.216.250")},
           doh={"y.example": A("93.184.216.185")},
           tcp={("93.184.216.250", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response")}),
     BASE + ["--baseline", "base.example:443", "y.example"],
     None, ["L2 는 정상"], ["로컬 회선·기기 문제", "인터넷 연결 장애"])

case("대조군 이름 해석 실패 — 회선 문제 아님",
     World(sys_dns={"x.example": A("93.184.216.180")},
           doh={"x.example": A("93.184.216.180")}),
     BASE + ["--baseline", "없는이름.invalid", "x.example"],
     None, ["대조군 없음"], ["회선 정상", "인터넷 연결 장애"])

# ── 프록시 ──
case("프록시 정책 거부",
     World(sys_dns={"px.example": A("93.184.216.190")},
           doh={"px.example": A("93.184.216.190")},
           proxy_deny="CONNECT 거부 403 Blocked by policy"),
     BASE + ["--proxy", "http://127.0.0.1:1", "px.example"], "L2c",
     ["프록시"], ["통신사"])

case("싱크홀 + 프록시 — 근본 원인은 DNS",
     # DNS 가 싱크홀을 반환하면 프록시 실패는 근본 원인이 아니다.
     World(sys_dns={"sp.example": A("0.0.0.0")},
           doh={"sp.example": A("93.184.216.200")},
           tcp={("93.184.216.200", 443): N.TcpResult(N.OPEN, 6)},
           proxy_deny="SOCKS5 거부: 호스트 도달 불가"),
     BASE + ["--proxy", "socks5://127.0.0.1:1", "sp.example"], "L3",
     ["싱크홀"], ["프록시 정책", "프록시가 목적지 거부"])


# ── RPKI·MSS ──
case("RPKI invalid — 권한 없는 AS 의 대역 광고",
     World(sys_dns={"hj.example": A("93.184.216.250")},
           doh={"hj.example": A("93.184.216.250")},
           rpki=("invalid", "")),
     IDENT + ["hj.example"], "L4b",
     ["하이재킹", "인증서 확인 필요"])

case("RPKI valid — 경고 없음",
     World(sys_dns={"ok2.example": A("93.184.216.251")},
           doh={"ok2.example": A("93.184.216.251")},
           rpki=("valid", "")),
     IDENT + ["ok2.example"], None, [], ["하이재킹"])

case("RPKI unknown — ROA 미등록은 경고하지 않음",
     World(sys_dns={"unk.example": A("93.184.216.252")},
           doh={"unk.example": A("93.184.216.252")},
           rpki=("unknown", "")),
     IDENT + ["unk.example"], None, [], ["하이재킹", "광고 권한 없음"])

case("MSS 1360 — MSS clamping 보고",
     World(sys_dns={"mss.example": A("93.184.216.253")},
           doh={"mss.example": A("93.184.216.253")},
           mss=1360),
     BASE + ["mss.example"], None,
     ["MSS clamping"], ["하이재킹"])

case("MSS 1460 — 보고 없음",
     World(sys_dns={"mss2.example": A("93.184.216.254")},
           doh={"mss2.example": A("93.184.216.254")},
           mss=1460),
     BASE + ["mss2.example"], None, [], ["MSS clamping", "매우 작음"])

# ── 듀얼스택 ──
case("IPv4 성공, IPv6 실패",
     World(sys_dns={"ds.example": A("93.184.216.220")},
           doh={"ds.example": A("93.184.216.220")},
           v6={"ds.example": A("2001:db8::1")},
           tcp={("2001:db8::1", 443): N.TcpResult(N.UNREACH, 3, "ENETUNREACH")}),
     BASE + ["ds.example"], None,
     ["IPv6", "간헐적 지연"], ["차단"])

case("IPv6 만 연결됨 — IPv4 경로 문제",
     World(sys_dns={"v6.example": A("93.184.216.230")},
           doh={"v6.example": A("93.184.216.230")},
           v6={"v6.example": A("2001:db8::2")},
           tcp={("93.184.216.230", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("2001:db8::2", 443): N.TcpResult(N.OPEN, 8)}),
     BASE + ["v6.example"], "L4",
     ["IPv6 연결 성공, IPv4 실패"])

case("로컬 IPv6 없음 — IPv6 실패를 지연 원인으로 보고하지 않음",
     World(sys_dns={"nv6.example": A("93.184.216.231")},
           doh={"nv6.example": A("93.184.216.231")},
           v6={"nv6.example": A("2001:db8::3")}, local_v6=False,
           tcp={("2001:db8::3", 443): N.TcpResult(N.UNREACH, 1, "EHOSTUNREACH")}),
     BASE + ["nv6.example"], None,
     ["로컬 IPv6 경로 없음"], ["간헐적 지연", "IPv6("])

case("IPv6 주소 대상 + 로컬 IPv6 없음 — 로컬 문제",
     World(local_v6=False,
           tcp={("2001:db8::4", 443): N.TcpResult(N.UNREACH, 1, "EHOSTUNREACH")},
           tcp_default=N.TcpResult(N.UNREACH, 1, "EHOSTUNREACH")),
     BASE + ["[2001:db8::4]:443"], "L4",
     ["로컬 IPv6 미지원", "[2001:db8::4]:443"], ["통신사", "경로 구간"])

case("하이픈으로 시작하는 이름 — 입력 오류",
     World(), BASE + ["--", "-bad.example"], "L4",
     ["하이픈", "주소·포트"], ["DNS"])

case("CDN 노드 장애 — 다른 IP 는 연결, DNS 문제로 판정하지 않음",
     World(sys_dns={"node.example": A("93.184.216.42")},
           doh={"node.example": A("93.184.216.43")},
           hop_meta={"93.184.216.42": meta("93.184.216.42", "13335"),
                     "93.184.216.43": meta("93.184.216.43", "13335")},
           tcp={("93.184.216.42", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.42", 80): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.42", 22): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                ("93.184.216.43", 443): N.TcpResult(N.OPEN, 6)}),
     BASE + ["node.example"], "L4",
     ["특정 서버(노드)", "다른 IP(93.184.216.43) 는 연결됨"], ["DNS 만 차단", "이중 차단"])

case("-6 + 로컬 IPv6 없음 — 로컬 환경 문제",
     World(sys_dns={"six.example": A("93.184.216.44")}, local_v6=False,
           v6={"six.example": A("2001:db8::5")},
           tcp={("2001:db8::5", 443): N.TcpResult(N.UNREACH, 1, "EHOSTUNREACH")},
           tcp_default=N.TcpResult(N.UNREACH, 1, "EHOSTUNREACH")),
     BASE + ["-6", "six.example"], "L0",
     ["로컬 IPv6 미지원"], ["이중 차단", "DNS 만 차단", "통신사"])

case("프록시 연결 불가 — 회선 문제로 판정하지 않음",
     World(sys_dns={"pd.example": A("93.184.216.45")}, doh={"pd.example": A("93.184.216.45")},
           tcp={("127.0.0.1", 1): N.TcpResult(N.REFUSED, 1, "ECONNREFUSED")}),
     BASE + ["--proxy", "http://127.0.0.1:1", "pd.example"], "L0",
     ["프록시 연결 불가", "에 연결할 수 없음"], ["통신사", "인터넷 회선"])

case("여러 IP 중 하나만 실패 — 다른 IP 연결되면 경고",
     World(sys_dns={"mi.example": A("93.184.216.70", "93.184.216.71")},
           doh={"mi.example": A("93.184.216.70", "93.184.216.71")},
           tcp={("93.184.216.70", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response")}),
     BASE + ["mi.example"], None, ["일부 서버 IP 실패"], ["목적지 서버", "경로 구간"])

case("목적지 홉 프로브 1개 손실 + TCP 정상 — 경로 손실로 판정하지 않음",
     World(sys_dns={"pl.example": A("93.184.216.72")}, doh={"pl.example": A("93.184.216.72")},
           hops=[hop(1, "10.0.0.1"), hop(2, "93.184.216.72", 5.0, 1, 2)]),
     FULL + ["pl.example"], None, ["ICMP 응답 일부 누락"], ["목적지까지 패킷 손실"])

case("프록시가 IP 주소 CONNECT 거부 — 회선 문제로 판정하지 않음",
     World(sys_dns={"pi.example": A("93.184.216.73")}, doh={"pi.example": A("93.184.216.73")},
           proxy_deny_ip=True),
     BASE + ["--proxy", "http://127.0.0.1:3128", "pi.example"], None,
     ["IP 주소 목적지 연결을 거부"], ["통신사", "인터넷 회선"])

case("로컬 방화벽 차단(EPERM) — 원격 드롭으로 판정하지 않음",
     World(sys_dns={"lb.example": A("93.184.216.74")}, doh={"lb.example": A("93.184.216.74")},
           tcp_default=N.TcpResult(N.LOCAL, 1, "EPERM")),
     BASE + ["lb.example"], "L4", ["로컬 방화벽"], ["패킷 드롭", "통신사"])

case("IP 주소 대상의 기본 인증서 — 검증 실패를 치명으로 보지 않음",
     World(tls=dict(OKCERT, verified=False, error="self-signed certificate", name_match=False)),
     BASE + ["93.184.216.75"], None, ["SNI 없음"], ["인증서 검증 실패"])

case("URL 질의 문자열 — 호스트에 포함하지 않음",
     World(sys_dns={"q.example": A("93.184.216.76")}, doh={"q.example": A("93.184.216.76")}),
     BASE + ["https://q.example?x=1"], None, ["/?x=1"], ["이름 해석 실패"])

case("https URL + 비표준 포트 — TLS 검사 수행",
     World(sys_dns={"tp.example": A("93.184.216.77")}, doh={"tp.example": A("93.184.216.77")},
           tls=dict(OKCERT, verified=False, error="certificate has expired", days_left=-1)),
     BASE + ["https://tp.example:8080/x"], "L5", ["만료"], [])

# ── 중간 응답(투명 프록시) ──
case("경로 12홉, TCP 연결 3홉 — 중간 장비 대리 응답",
     World(sys_dns={"mid.example": A("93.184.216.240")},
           doh={"mid.example": A("93.184.216.240")},
           ttl_dist=3,
           hops=[hop(i, f"10.0.0.{i}") for i in range(1, 12)]
                + [hop(12, "93.184.216.240")]),
     FULL + ["mid.example"], "L4",
     ["중간 장비가 목적지 대신 응답"])

case("TCP 거리와 경로 거리 일치 — 보고 없음",
     World(sys_dns={"nrm.example": A("93.184.216.245")},
           doh={"nrm.example": A("93.184.216.245")},
           ttl_dist=12,
           hops=[hop(i, f"10.0.0.{i}") for i in range(1, 12)]
                + [hop(12, "93.184.216.245")]),
     FULL + ["nrm.example"], None, [], ["대신 응답"])

# ── 입력 ──
case("잘못된 포트 — 입력 오류",
     World(), BASE + ["a.example:99999"], "L4",
     ["주소·포트"], ["통신사", "경로 구간"])


# ─────────────────────── 실행 ───────────────────────

def root_layer(findings) -> Optional[str]:
    crit = [f.layer for f in findings if f.level == N.CRIT]
    if not crit:
        return None
    return sorted(set(crit),
                  key=lambda l: N.LAYER_ORDER.index(l) if l in N.LAYER_ORDER else 99)[0]


def main(argv: list[str]) -> int:
    pick = argv[0] if argv else ""
    passed = failed = 0
    problems: list[str] = []

    for name, world, args, want_root, must, must_not in CASES:
        if pick and pick not in name:
            continue
        try:
            rc, findings, out = diagnose(world, args)
        except BaseException as ex:            # 진단 중 예외는 실패로 처리
            failed += 1
            problems.append(f"{name}\n    예외: {type(ex).__name__}: {ex}")
            continue

        got_root = root_layer(findings)
        blob = out + " " + " ".join(f.message for f in findings)
        # must_not 은 원인 구간 줄과 발견 사항에만 적용한다 (섹션 제목·행 문구 제외).
        blame = " ".join(ln for ln in out.splitlines() if "→" in ln and "원인 구간" in ln)
        verdict_text = blame + " " + " ".join(f.message for f in findings)
        errs = []
        if got_root != want_root:
            errs.append(f"근본 원인 계층: 기대 {want_root} → 실제 {got_root}")
        for m in must:
            if m not in blob:
                errs.append(f"누락 문구: {m!r}")
        for m in must_not:
            if m in verdict_text:
                errs.append(f"불필요 문구: {m!r}")
        if want_root is None and rc != 0:
            errs.append(f"종료 코드: 기대 0 → 실제 {rc}" + (" (내부 오류)" if rc == 3 else ""))
        if "내부 오류" in out:
            errs.append("진단 중 내부 오류 발생: " + next(
                ln.strip() for ln in out.splitlines() if "내부 오류" in ln))
        if want_root and rc != 1:
            errs.append(f"종료 코드: 기대 1 → 실제 {rc}")

        if errs:
            failed += 1
            problems.append(name + "\n    " + "\n    ".join(errs))
        else:
            passed += 1
            print(f"  ok   {name}")

    for name, fn in (("stub 시그니처 일치", check_stub_signatures),
                     ("여러 대상 — 대상별 판정 분리", check_multi_target),
                     ("반복 관측 — 상시/간헐 실패 구분", check_watch),
                     ("중단 — 실행 중인 외부 명령 종료", check_abort),
                     ("연결 오류 코드 분류", check_errno),
                     ("반복 관측 + 보고서", check_watch_report),
                     ("보고서 — 필수 항목 포함", check_report)):
        if pick and pick not in name:
            continue
        try:
            errs = fn()
        except BaseException as ex:
            errs = [f"예외: {type(ex).__name__}: {ex}"]
        if errs:
            failed += 1
            problems.append(name + "\n    " + "\n    ".join(errs))
        else:
            passed += 1
            print(f"  ok   {name}")

    for p in problems:
        print(f"  FAIL {p}")
    print(f"\n{passed} 통과 / {failed} 실패 / {passed + failed} 시나리오")
    return 1 if failed else 0


# ─────────────── 반복 관측·보고서 ───────────────

def check_watch() -> list[str]:
    import time as _t
    st = N.Style(False, True)
    now = _t.time()

    def snap(t, root):
        return N.Snapshot(t, 1 if root else 0, {"a.example": root},
                          {"a.example": [f"{root} 실패"] if root else []})

    def summary(hist):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            N.watch_summary(hist, st)
        return buf.getvalue()

    errs = []
    o = summary([snap(now + i * 10, "L4") for i in range(5)])
    if "상시 실패" not in o or "5/5" not in o:
        errs.append("전 회차 실패가 '상시 실패' 로 표시되지 않음")
    o = summary([snap(now, "L4"), snap(now + 10, None), snap(now + 20, "L4"),
                 snap(now + 30, None), snap(now + 40, None)])
    if "간헐 실패" not in o or "2/5" not in o:
        errs.append("일부 회차 실패가 '간헐 실패' 로 표시되지 않음")
    if "상시 실패" in o:
        errs.append("간헐 실패가 '상시 실패' 로 표시됨")
    o = summary([snap(now + i * 10, None) for i in range(4)])
    if "모두 정상" not in o:
        errs.append("전 회차 정상이 '모두 정상' 으로 표시되지 않음")
    o = summary([snap(now, "L4"), snap(now + 10, "L6"), snap(now + 20, "L6")])
    if "결론 변경" not in o:
        errs.append("결론 변경 횟수가 표시되지 않음")
    with contextlib.redirect_stdout(io.StringIO()):
        lines = N.watch_summary([snap(now, "L4"), snap(now + 10, None)], st)
    if not lines or not any("1/2" in ln for ln in lines):
        errs.append("watch_summary 가 보고서용 줄을 돌려주지 않음")
    return errs


def check_watch_report() -> list[str]:
    """--watch 와 --report 를 함께 쓰면 마지막 회차 결과와 반복 관측 요약을 저장한다."""
    import tempfile
    w = World(sys_dns={"wr.example": A("93.184.216.215")},
              doh={"wr.example": A("93.184.216.215")})
    install(w)
    path = os.path.join(tempfile.gettempdir(), "netcheck_test_watch.md")
    if os.path.exists(path):
        os.unlink(path)
    a = N.parse_args(BASE + ["--no-color", "--watch", "1", "--count", "1",
                             "--report", path, "wr.example"])
    a.color = False
    with contextlib.redirect_stdout(io.StringIO()):
        N.watch_loop(a)
    if not os.path.exists(path):
        return ["보고서 파일이 생성되지 않음"]
    txt = open(path, encoding="utf-8").read()
    os.unlink(path)
    errs = []
    for need in ("반복 관측", "wr.example", "모두 정상", "전체 진단 출력"):
        if need not in txt:
            errs.append(f"보고서에 누락: {need!r}")
    return errs


def check_errno() -> list[str]:
    """connect 오류 코드 → 상태 분류 (실제 tcp_probe)."""
    import errno as _e
    cases = {_e.EPERM: N.LOCAL, _e.EACCES: N.LOCAL, _e.ECONNREFUSED: N.REFUSED,
             _e.EHOSTUNREACH: N.UNREACH, _e.ECONNRESET: N.RESET}
    orig = N.open_stream
    errs = []
    try:
        for code, want in cases.items():
            def boom(*a, _c=code, **k):
                raise OSError(_c, "test")
            N.open_stream = boom
            got = _REAL_TCP_PROBE("192.0.2.1", 443, 1).status
            if got != want:
                errs.append(f"{_e.errorcode[code]} → 기대 {want}, 실제 {got}")
        N.open_stream = lambda *a, **k: (_ for _ in ()).throw(N.ProxyError("x", N.UNREACH))
        got = _REAL_TCP_PROBE("192.0.2.1", 443, 1).status
        if got != N.UNREACH:
            errs.append(f"프록시 502 → 기대 UNREACH, 실제 {got}")
    finally:
        N.open_stream = orig
    return errs


def check_abort() -> list[str]:
    """중단 요청 시 실행 중인 외부 명령을 즉시 종료한다."""
    import time as _t

    class Stop(BaseException):
        pass

    t0 = _t.monotonic()
    deadline = t0 + 0.6

    def abort():
        if _t.monotonic() > deadline:
            raise Stop()

    cmd = ([sys.executable, "-c", "import time; time.sleep(10)"])
    N.ABORT = abort
    try:
        N.run_cmd(cmd, 30)
        return ["중단 요청 후에도 명령이 끝까지 실행됨"]
    except Stop:
        took = _t.monotonic() - t0
        return [] if took < 2 else [f"중단까지 {took:.1f}초 소요"]
    finally:
        N.ABORT = None


def check_multi_target() -> list[str]:
    """대상이 여럿이면 판정이 대상별로 분리돼야 한다."""
    errs = []
    w = World(sys_dns={"bad.example": A("0.0.0.0"), "good.example": A("93.184.216.11")},
              doh={"bad.example": A("93.184.216.10"), "good.example": A("93.184.216.11")})
    rc, findings, out = diagnose(w, BASE + ["bad.example", "good.example"])
    install(w)
    a = N.parse_args(BASE + ["--no-color", "bad.example", "good.example"])
    a.color = False
    with contextlib.redirect_stdout(io.StringIO()):
        nc, targets = N.run_diagnosis(a)
        nc.verdict(targets)
        nc.pool.shutdown(wait=False)
    if nc.rep.crit_layers("bad.example")[:1] != ["L3"]:
        errs.append(f"bad.example 근본 원인: 기대 L3 → 실제 {nc.rep.crit_layers('bad.example')}")
    if nc.rep.crit_layers("good.example"):
        errs.append(f"good.example 에 다른 대상의 실패가 포함됨: {nc.rep.crit_layers('good.example')}")
    if "good.example" not in out or "문제 없음" not in out:
        errs.append("good.example 이 '문제 없음' 으로 표시되지 않음")

    snap = N.snapshot(nc, targets)
    if snap.roots.get("good.example") is not None:
        errs.append("snapshot 에서 good.example 이 실패로 기록됨")
    if snap.roots.get("bad.example") != "L3":
        errs.append("snapshot 에서 bad.example 근본 원인 불일치")

    # 같은 호스트·다른 포트는 host:port 로 분리돼야 한다
    w3 = World(sys_dns={"d.example": A("93.184.216.14")}, doh={"d.example": A("93.184.216.14")},
               tcp={("93.184.216.14", 443): N.TcpResult(N.TIMEOUT, 4000, "no-response"),
                    ("93.184.216.14", 22): N.TcpResult(N.TIMEOUT, 4000, "no-response")})
    install(w3)
    a3 = N.parse_args(["--no-color"] + BASE + ["d.example:443", "d.example:80", "d.example:443"])
    a3.color = False
    with contextlib.redirect_stdout(io.StringIO()):
        nc3, t3 = N.run_diagnosis(a3)
        nc3.verdict(t3)
        nc3.pool.shutdown(wait=False)
    keys = [t.key for t in t3]
    if keys != ["d.example:443", "d.example:80"]:
        errs.append(f"같은 호스트 대상 키: 기대 [d.example:443, d.example:80] → 실제 {keys}")
    if (nc3.rep.crit_layers("d.example:443") or [None])[0] != "L4":
        errs.append(f"d.example:443 근본 원인: 기대 L4 → 실제 {nc3.rep.crit_layers('d.example:443')}")
    if nc3.rep.crit_layers("d.example:80"):
        errs.append(f"d.example:80 에 다른 포트의 실패가 포함됨: {nc3.rep.crit_layers('d.example:80')}")
    pl = N.to_payload(nc3, t3, a3)
    if [t["key"] for t in pl["targets"]] != keys or pl["invalid_targets"]:
        errs.append("payload 대상 키 불일치 또는 잘못된 invalid_targets")

    # 공통 실패(회선 불통)는 모든 대상에 적용돼야 한다
    w2 = World(sys_dns={"x.example": A("93.184.216.12"), "y.example": A("93.184.216.13")},
               doh={}, all_down=True,
               tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response"))
    install(w2)
    a2 = N.parse_args(BASE + ["--no-color", "x.example", "y.example"])
    a2.color = False
    with contextlib.redirect_stdout(io.StringIO()):
        nc2, t2 = N.run_diagnosis(a2)
        nc2.verdict(t2)
        nc2.pool.shutdown(wait=False)
    for h in ("x.example", "y.example"):
        if (nc2.rep.crit_layers(h) or [None])[0] != "L2":
            errs.append(f"{h} 근본 원인이 L2 가 아님: {nc2.rep.crit_layers(h)}")
    return errs


def check_report() -> list[str]:
    """보고서에 문의용 필수 항목이 포함되는지 확인한다."""
    import tempfile
    w = World(sys_dns={"rep.example": A("93.184.216.210")},
              doh={"rep.example": A("93.184.216.210")},
              tcp_default=N.TcpResult(N.TIMEOUT, 4000, "no-response"),
              hops=[hop(1, "10.0.0.1"), hop(2, "100.64.1.1"), hop(3, None, None, 0, 2)])
    install(w)
    a = N.parse_args(["-m", "8", "-r", "1", "--no-color", "rep.example"])
    a.color = False
    with contextlib.redirect_stdout(io.StringIO()):
        nc, targets = N.run_diagnosis(a)
        nc.verdict(targets)
        nc.pool.shutdown(wait=False)
    path = os.path.join(tempfile.gettempdir(), "netcheck_test_report.md")
    N.write_report(path, nc, targets, a, "원본 출력 \x1b[31m색\x1b[0m")
    txt = open(path, encoding="utf-8").read()
    os.unlink(path)
    errs = []
    for need, why in [("공인 IP", "공인 IP"),
                      ("rep.example", "대상"),
                      ("마지막 응답 홉", "마지막 응답 홉"),
                      ("100.64.1.1", "경로 표의 홉"),
                      ("결과 활용", "결과 활용 안내"),
                      ("원본 출력", "전체 출력 첨부")]:
        if need not in txt:
            errs.append(f"보고서에 누락: {why} ({need!r})")
    if "\x1b[" in txt:
        errs.append("보고서에 ANSI 색 코드가 남아 있음")
    return errs


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
