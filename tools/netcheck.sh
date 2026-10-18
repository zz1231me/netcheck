#!/bin/bash
# netcheck — 계층별 도달성 진단
#
# "안 된다"를 "어느 계층 · 어느 구간에서 끊겼다"로 바꾼다.
# 각 계층을 서로 다른 방법으로 독립 검증하고, 정상 대조군과 나란히 비교한 뒤,
# 책임 구간과 다음 행동을 결론으로 낸다.
#
#   ./tools/netcheck.sh apis.data.go.kr
#   ./tools/netcheck.sh -f apis.data.go.kr:443 www.weather.go.kr:443
#   ./tools/netcheck.sh --json apis.data.go.kr > report.json
#
# 의존: dig curl nc traceroute whois awk  (선택: python3 jq openssl)
# 대상: macOS / Linux, bash 3.2+

set -u
umask 077

VERSION="2.2"
SELF=$(basename "$0")

# ─────────────────────────────── 기본값 ───────────────────────────────
DEF_PORT=443
TMO=4                  # 단일 연결 타임아웃(초)
REPEAT=3               # TCP 반복 횟수 — 간헐 장애 판별용
INTERVAL=0             # 반복 사이 간격(초) — 시간에 걸친 장애를 볼 때
MAXHOP=20
TRQ=2                  # traceroute 홉당 프로브 수 — 손실률 계산용
IPV=auto               # auto | 4 | 6
MODE=normal            # quick | normal | full
JSON=0
COLOR=auto
BASELINE_RAW=""
TRACE=1

# 대조군: 서로 다른 AS·서로 다른 대륙. 회선 자체의 건강을 본다.
DEF_BASELINE="1.1.1.1:443 8.8.8.8:443 www.google.com:443"
# DNS 진실 확인용 — IP 리터럴로 붙기 때문에 DNS 가로채기의 영향을 받지 않는다.
DOH_HOST=cloudflare-dns.com
DOH_IP=1.1.1.1
DOH2_HOST=dns.google
DOH2_IP=8.8.8.8

usage() {
  cat <<USAGE
$SELF v$VERSION — 계층별 도달성 진단

사용법
  $SELF [옵션] <호스트[:포트]> [호스트[:포트] ...]

옵션
  -p, --port N        기본 포트 (기본 $DEF_PORT)
  -t, --timeout N     연결 타임아웃 초 (기본 $TMO)
  -r, --repeat N      TCP 반복 횟수 (기본 $REPEAT) — 간헐 장애 판별
  -i, --interval N    반복 사이 간격 초 (기본 0) — 시간에 걸친 장애를 볼 때
  -m, --max-hop N     traceroute 최대 홉 (기본 $MAXHOP)
  -4 | -6             IPv4 / IPv6 강제 (기본: 둘 다 조사)
  -q, --quick         경로·신원·도메인 조사 생략 (빠름)
  -f, --full          전체: 경로 추적·PMTU·포트 스윕까지
      --no-trace      traceroute 만 생략
      --baseline "a:1,b:2"   대조군 교체
      --json          JSON 출력 (사람용 출력 없음)
      --no-color      색 끄기
  -h, --help          이 도움말

검사 계층
  L0  내 기기 · 공인 IP · NAT · VPN · 프록시
  L1  공유기        L2  인터넷(DNS 없이)   L2b 회선 대조(회선이 둘 이상일 때)
  L3  DNS(DoH 대조) L3b 도메인 등록·권위 서버
  L4  TCP(실패 원인 구분)  L4b 목적지 신원(소유자·대역·신고처·열린 포트)
  L5  TLS(인증서·SNI)      L6  HTTP(이동 경로·중간 경유)
  L7  경로(AS·손실률·역방향이름·역경로)   L8 PMTU   L9 대조군

  L2b 는 회선이 둘 이상 붙어 있을 때만 나온다. 휴대폰 테더링을 켜 두면
  "다른 회선에서는 되는가" 를 자동으로 비교한다 — 이게 통신사 경로 문제와
  상대 망 장애를 가르는 결정적 증거다.

읽는 법
  L0~L2 가 실패하면 그 아래는 볼 필요가 없다 — 내 쪽 문제다.
  L3(DNS)만 다르면 이름 문제, L4(TCP)에서 멈추면 경로·방화벽,
  L5(TLS)에서 멈추면 인증서·중간자, L6(HTTP)까지 갔으면 망은 정상이고
  애플리케이션 문제다. 결론은 마지막 [판정] 절에 나온다.

예시
  $SELF apis.data.go.kr                     # 한 곳
  $SELF apis.data.go.kr www.weather.go.kr   # 의심 + 정상 나란히
  $SELF -f -r 10 flaky.example.com          # 간헐 장애 추적
USAGE
}

die() { printf '%s: %s\n' "$SELF" "$*" >&2; exit 2; }
# 숫자 옵션 검사. die 는 명령 치환 안에서 부르면 서브셸만 끝나므로,
# 검사는 반드시 파싱 루프와 같은 셸에서 해야 한다.
isnum() { case "${1:-}" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }

# ─────────────────────────────── 인자 ───────────────────────────────
TARGETS=""
while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port)     isnum "${2:-}" || die "$1 에는 숫자가 필요하다: ${2:-<없음>}"; DEF_PORT=$2; shift 2;;
    -t|--timeout)  isnum "${2:-}" || die "$1 에는 숫자가 필요하다: ${2:-<없음>}"; TMO=$2; shift 2;;
    -r|--repeat)   isnum "${2:-}" || die "$1 에는 숫자가 필요하다: ${2:-<없음>}"; REPEAT=$2; shift 2;;
    -i|--interval) isnum "${2:-}" || die "$1 에는 숫자가 필요하다: ${2:-<없음>}"; INTERVAL=$2; shift 2;;
    -m|--max-hop)  isnum "${2:-}" || die "$1 에는 숫자가 필요하다: ${2:-<없음>}"; MAXHOP=$2; shift 2;;
    -4)            IPV=4; shift;;
    -6)            IPV=6; shift;;
    -q|--quick)    MODE=quick; TRACE=0; shift;;
    -f|--full)     MODE=full; TRQ=3; shift;;
    --no-trace)    TRACE=0; shift;;
    --baseline)    [ -n "${2:-}" ] || die "$1 에는 값이 필요하다"; BASELINE_RAW=$2; shift 2;;
    --json)        JSON=1; COLOR=off; shift;;
    --no-color)    COLOR=off; shift;;
    -h|--help)     usage; exit 0;;
    -*)            die "알 수 없는 옵션: $1  ($SELF -h)";;
    *)             TARGETS="$TARGETS $1"; shift;;
  esac
done
[ -n "${TARGETS# }" ] || { usage >&2; exit 2; }
valid_port_arg() { case "$1" in ''|*[!0-9]*) return 1;; *) [ "$1" -ge 1 ] && [ "$1" -le 65535 ];; esac; }
valid_port_arg "$DEF_PORT" || die "포트 범위를 벗어났다: $DEF_PORT (1~65535)"
[ "$TMO" -ge 1 ] 2>/dev/null || die "타임아웃은 1 이상이어야 한다: $TMO"
[ "$REPEAT" -ge 1 ] 2>/dev/null || die "반복 횟수는 1 이상이어야 한다: $REPEAT"
[ "$MAXHOP" -ge 1 ] 2>/dev/null || die "홉 수는 1 이상이어야 한다: $MAXHOP"

BASELINE=$(printf '%s' "${BASELINE_RAW:-$DEF_BASELINE}" | tr ',' ' ')

# ─────────────────────────────── 출력 ───────────────────────────────
if [ "$COLOR" = auto ] && [ -t 1 ]; then COLOR=on; fi
if [ "$COLOR" = on ]; then
  C_RST=$'\033[0m'; C_DIM=$'\033[2m'; C_B=$'\033[1m'
  C_OK=$'\033[32m'; C_NG=$'\033[31m'; C_WN=$'\033[33m'; C_IN=$'\033[36m'
else
  C_RST=; C_DIM=; C_B=; C_OK=; C_NG=; C_WN=; C_IN=
fi

OK="${C_OK}✔${C_RST}"; NG="${C_NG}✘${C_RST}"; WN="${C_WN}⚠${C_RST}"; IN="${C_DIM}·${C_RST}"

# 한글은 터미널에서 두 칸을 차지하는데 printf 의 %-Ns 는 글자 수로 센다.
# 그대로 두면 한글이 섞인 표가 전부 어긋난다 — 표시 폭으로 직접 채운다.
pad() { # 문자열 목표폭 → 문자열 + 여백
  # 값에 $ 나 백틱이 들어올 수 있으므로 확장이 일어나지 않는 경로로만 넘긴다.
  printf '%s\n' "$1" | LC_ALL=C awk -v w="$2" '{
    s = $0; n = 0
    for (i = 1; i <= length(s); i++) {
      c = substr(s, i, 1)
      # UTF-8 선두 바이트만 센다 (계속 바이트 0x80~0xBF 는 건너뛴다)
      if (c < "\200")            { n += 1 }
      else if (c >= "\340")      { n += 2 }   # 3바이트 이상 = 한글·CJK = 두 칸
      else if (c >= "\300")      { n += 1 }   # 2바이트 = 한 칸
    }
    pad = ""
    while (n + length(pad) < w) pad = pad " "
    printf "%s%s", s, pad
    exit
  }'
}
say()  { [ "$JSON" = 1 ] || printf '%s\n' "$*"; }
sect() { [ "$JSON" = 1 ] || printf '\n%s%s%s\n' "$C_B" "$*" "$C_RST"; }
row()  { [ "$JSON" = 1 ] || printf '  %s %s %s\n' "$1" "$(pad "$2" 15)" "$3"; }
note() { [ "$JSON" = 1 ] || printf '      %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/netcheck.XXXXXX") || die "임시 디렉터리 실패"
trap 'rm -rf "$WORK"' EXIT INT TERM

# 키-값 저장소 (bash 3.2 에는 연관배열이 없다)
kset() { printf '%s' "$2" > "$WORK/kv.$1"; }
kget() { [ -f "$WORK/kv.$1" ] && cat "$WORK/kv.$1" || printf '%s' "${2:-}"; }

# 결론 수집: 등급|계층|메시지
FIND="$WORK/findings"; : > "$FIND"
finding() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$FIND"; }

# 이식 가능한 timeout
runto() {
  local t=$1; shift
  "$@" & local p=$!
  # 감시 서브셸의 출력을 반드시 버려야 한다. 안 그러면 이 서브셸(과 그 안의 sleep)이
  # 명령 치환의 출력 파이프를 붙들고 있어, 명령이 즉시 끝나도 $( ) 가
  # 타임아웃 시간만큼 통째로 기다린다 — 조용히 전체를 몇 배 느리게 만드는 함정이다.
  ( sleep "$t"; kill -TERM $p 2>/dev/null ) >/dev/null 2>&1 & local w=$!
  wait $p 2>/dev/null; local rc=$?
  kill -TERM $w 2>/dev/null; wait $w 2>/dev/null
  return $rc
}

have() { command -v "$1" >/dev/null 2>&1; }
PY=""
for p in /usr/bin/python3 python3; do have "$p" && { PY=$p; break; }; done
HAVE_JQ=0; have jq && HAVE_JQ=1
HAVE_SSL=0; have openssl && HAVE_SSL=1

# ══════════════════════════════ 기본 프로브 ══════════════════════════════

# TCP 한 번 붙어 보고, 실패를 "왜"까지 구분한다.
#   OPEN       3-way 성공
#   TIMEOUT    아무 응답 없음 → 조용히 버려짐(방화벽 DROP·널라우팅·경로 단절)
#   REFUSED    RST 수신      → 호스트는 살아 있고 그 포트만 닫혔다
#   UNREACH    ICMP unreachable → 라우터가 못 간다고 알려 준 것
#   RESET      붙었다가 즉시 끊김 → 중간 검열장비 또는 서버 거부
# 이 구분이 진단의 절반이다. nc 는 이걸 뭉뚱그린다.
valid_port() { case "$1" in ''|*[!0-9]*) return 1;; *) [ "$1" -ge 1 ] && [ "$1" -le 65535 ];; esac; }

tcp_probe() { # ip port [출발지IP]  →  "STATUS ms detail"
  local ip=$1 port=$2 src=${3:-}
  valid_port "$port" || { echo "ERROR 0 bad-port"; return; }
  if [ -n "$PY" ]; then
    "$PY" - "$ip" "$port" "$TMO" "$src" <<'PYEOF'
import socket, sys, time, errno
ip, port, tmo = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
src = sys.argv[4] if len(sys.argv) > 4 else ""
fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM); s.settimeout(tmo)
# 출발지를 묶으면 그 인터페이스(회선)로만 나간다 — 회선끼리 비교할 때 쓴다.
if src:
    try: s.bind((src, 0))
    except OSError as e: print("ERROR 0 bind-%s" % errno.errorcode.get(e.errno, e.errno)); raise SystemExit
t0 = time.time()
def ms(): return int((time.time() - t0) * 1000)
try:
    s.connect((ip, port))
    print("OPEN %d -" % ms())
except socket.timeout:
    print("TIMEOUT %d no-response" % ms())
except OSError as e:
    n = e.errno
    name = errno.errorcode.get(n, str(n))
    if n == errno.ECONNREFUSED:                       st = "REFUSED"
    elif n in (errno.EHOSTUNREACH, errno.ENETUNREACH): st = "UNREACH"
    elif n == errno.ECONNRESET:                        st = "RESET"
    elif n == errno.ETIMEDOUT:                         st = "TIMEOUT"
    else:                                              st = "ERROR"
    print("%s %d %s" % (st, ms(), name))
finally:
    s.close()
PYEOF
  else
    # python3 이 없을 때: nc 로 열림/막힘만. 이유 구분은 포기한다.
    local t0 t1
    t0=$(date +%s)
    if nc -z -G "$TMO" -w "$TMO" "$ip" "$port" >/dev/null 2>&1; then
      t1=$(date +%s); echo "OPEN $(( (t1-t0)*1000 )) -"
    else
      t1=$(date +%s); echo "TIMEOUT $(( (t1-t0)*1000 )) nc-only"
    fi
  fi
}

# REPEAT 회 반복 → "성공수/시도수 최소ms 평균ms 최대ms 대표상태 상세"
# 한 번만 재고 판단하면 간헐 장애를 놓친다.
tcp_probe_n() { # ip port [n] [출발지IP]
  local ip=$1 port=$2 n=${3:-$REPEAT} src=${4:-} i=0 ok=0 st detail last="" res
  local mn=999999 mx=0 sum=0 ms
  while [ $i -lt "$n" ]; do
    [ $i -gt 0 ] && [ "$INTERVAL" != 0 ] && sleep "$INTERVAL"
    res=$(tcp_probe "$ip" "$port" "$src")
    # 프로브 자체가 죽으면(파이썬 부재·중단) 빈 줄이 온다. 조용히 "성공" 으로
    # 넘어가지 않도록 명시적으로 실패 처리한다.
    [ -n "$res" ] || res="ERROR 0 probe-failed"
    st=${res%% *}; ms=$(echo "$res" | awk '{print $2}'); detail=$(echo "$res" | awk '{print $3}')
    case "$ms" in ''|*[!0-9]*) ms=0;; esac
    [ "$st" = OPEN ] && { ok=$((ok+1)); sum=$((sum+ms))
      [ "$ms" -lt "$mn" ] && mn=$ms; [ "$ms" -gt "$mx" ] && mx=$ms; }
    [ "$st" != OPEN ] && last="$st $detail"
    i=$((i+1))
  done
  if [ $ok -gt 0 ]; then
    echo "$ok/$n $mn $((sum/ok)) $mx OPEN ${last:-–}"
  else
    echo "$ok/$n - - - ${last% *} ${last#* }"
  fi
}

# ─────────────────────────── IP 성격 판정 ───────────────────────────
# 구간을 나누는 것은 홉 번호가 아니라 주소의 성격과 소유자다.
ip_class() { # ip → 한 줄 설명
  case "$1" in
    10.*|192.168.*) echo "사설(RFC1918)";;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) echo "사설(RFC1918)";;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) echo "CGNAT(RFC6598)";;
    169.254.*) echo "링크로컬 — DHCP 실패";;
    127.*) echo "루프백";;
    0.0.0.0) echo "널 — 싱크홀";;
    224.*|22[5-9].*|23[0-9].*) echo "멀티캐스트";;
    192.0.2.*|198.51.100.*|203.0.113.*) echo "문서용(RFC5737)";;
    198.1[89].*) echo "벤치마크(RFC2544)";;
    192.0.0.*) echo "IETF 예약";;
    24[0-9].*|25[0-5].*) echo "예약(RFC1112)";;
    ::ffff:*) echo "v4 매핑";;
    64:ff9b:*) echo "NAT64";;
    2002:*) echo "6to4";;
    fe80:*) echo "링크로컬 v6";;
    fc*:*|fd*:*) echo "ULA v6";;
    ::1) echo "루프백 v6";;
    ::) echo "널 v6 — 싱크홀";;
    *) echo "공인";;
  esac
}
is_private() { case "$(ip_class "$1")" in 공인) return 1;; *) return 0;; esac; }
# IP 목록은 공백으로도 줄바꿈으로도 온다. 첫 주소 하나만 안전하게 뽑는다.
first_ip() { printf '%s' "$1" | awk '{print $1; exit}'; }
# 이름과 IP 를 함께 쓰되, 이름 자체가 IP 면 되풀이하지 않는다.
hp() { if [ "$1" = "$2" ]; then printf '%s' "$1"; else printf '%s(%s)' "$1" "$2"; fi; }
is_sinkhole() { case "$1" in 0.0.0.0|127.*|::|::1) return 0;; *) return 1;; esac; }

# 밀리초 시계. BSD date 는 %N 을 모르는 판이 있어 파이썬으로 물러선다.
now_ms() {
  local t
  t=$(date +%s%N 2>/dev/null)
  case "$t" in
    *[!0-9]*|'') if [ -n "$PY" ]; then "$PY" -c 'import time;print(int(time.time()*1000))'
                 else echo $(( $(date +%s) * 1000 )); fi;;
    *) echo $(( t / 1000000 ));;
  esac
}

# 호스트명인가 IP 인가. IPv6 리터럴에는 a~f 가 들어가므로 글자 유무로 판단하면 안 된다.
is_ip_literal() {
  case "$1" in
    *:*) case "$1" in *[!0-9a-fA-F:.]*) return 1;; *) return 0;; esac;;
    *[!0-9.]*) return 1;;
    *.*) return 0;;
    *) return 1;;
  esac
}

# ─────────────────────────── 소유자 / AS ───────────────────────────
# 홉 IP 가 누구 것인지 알아야 "여기까지가 우리 ISP" 라고 말할 수 있다.
asn_of() { # ip → "AS번호 이름"  (캐시)
  local ip=$1
  local f
  f="$WORK/asn.$(printf '%s' "$ip" | tr ':.' '__')"
  [ -f "$f" ] && { cat "$f"; return; }
  if is_private "$ip"; then
    printf '%s' "- $(ip_class "$ip")" > "$f"; cat "$f"; return
  fi
  local num name out
  num=$(ipmeta "$ip" 1); name=$(ipmeta "$ip" 7)
  out="$num $name"
  case "$out" in
    "NA "*|"NA"|"NA ") out="NA 전역 라우팅 없음(BGP 미광고)";;
    "- 조회실패") out=$(rirfield "$ip" 'descr|org-name|orgname|OrgName|netname|NetName')
                  [ -n "$out" ] && out="? $out" || out="- 조회실패";;
  esac
  [ -n "${out# }" ] || out="- 조회실패"
  printf '%s' "$out" > "$f"; cat "$f"
}

# ═══════════════════ IP 신원 조사 (한 번 물어 캐시한다) ═══════════════════

# Team Cymru 한 줄에 AS·대역·국가·등록기관·할당일이 다 들어 있다.
#   AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
ipmeta() { # ip field(1~7) → 값
  local ip=$1 n=$2 f
  f="$WORK/meta.$(printf '%s' "$ip" | tr ':.' '__')"
  if [ ! -f "$f" ]; then
    if is_private "$ip"; then
      printf -- '- | %s | - | - | - | - | %s\n' "$ip" "$(ip_class "$ip")" > "$f"
    else
      runto 7 whois -h whois.cymru.com " -v $ip" 2>/dev/null | awk 'NR==2' > "$f"
      [ -s "$f" ] || printf -- '- | %s | - | - | - | - | 조회실패\n' "$ip" > "$f"
    fi
  fi
  awk -F'[|]' -v n="$n" '{gsub(/^ +| +$/,"",$n); print $n}' "$f"
}

# 등록 정보(RIR whois). 같은 IP 를 두 번 묻지 않는다.
rirwhois() { # ip → 원문 (캐시)
  local ip=$1 f
  f="$WORK/rir.$(printf '%s' "$ip" | tr ':.' '__')"
  [ -f "$f" ] || runto 9 whois "$ip" 2>/dev/null > "$f"
  cat "$f"
}

# whois 는 큰 대역부터 작은 대역 순으로 여러 블록을 준다.
# 우리가 원하는 것은 **가장 구체적인** 블록 = 마지막 값이다.
rirfield() { # ip 필드이름들(정규식) → 마지막 값
  rirwhois "$1" | awk -v pat="^($2):" '
    BEGIN{IGNORECASE=1}
    $0 ~ pat { sub(/^[^:]*: *(  *)?/,""); gsub(/^ +| +$/,""); if ($0 != "") v=$0 }
    END{ print v }'
}

# 역방향 이름. 라우터 이름에는 도시·역할·회선 종류가 자주 박혀 있다.
ptr_of() { # ip → 이름 또는 빈 문자열 (캐시)
  local ip=$1 f
  f="$WORK/ptr.$(printf '%s' "$ip" | tr ':.' '__')"
  if [ ! -f "$f" ]; then
    if is_private "$ip"; then : > "$f"
    else dig +tries=1 +time=2 +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' > "$f"
    fi
  fi
  cat "$f"
}

# AS 이름과 역방향 이름으로 "이게 어떤 종류의 대상인가" 를 짐작한다.
# 확정이 아니라 힌트다 — 다만 CDN 이면 "내 IP 만 차단" 가설이 크게 약해진다.
# Cymru 의 AS 이름은 "핸들 - 회사명, 국가" 꼴이다. 회사명만 남긴다.
as_short() { printf '%s' "$1" | sed 's/^[^ ]* - //; s/, [A-Z][A-Z]$//' | cut -c1-26; }

ip_kind() { # ip → 성격
  local n
  n=$(printf '%s %s' "$(ipmeta "$1" 7)" "$(ptr_of "$1")" | tr 'A-Z' 'a-z')
  case "$n" in
    *cloudflare*)                      echo "CDN — Cloudflare";;
    *akamai*)                          echo "CDN — Akamai";;
    *fastly*)                          echo "CDN — Fastly";;
    *cloudfront*|*amazon*|*aws*)       echo "클라우드 — AWS";;
    *google*|*gcp*)                    echo "클라우드 — Google";;
    *microsoft*|*azure*)               echo "클라우드 — Azure";;
    *alibaba*|*aliyun*)                echo "클라우드 — Alibaba";;
    *oracle*)                          echo "클라우드 — Oracle";;
    *digitalocean*|*linode*|*vultr*|*hetzner*|*ovh*) echo "VPS 호스팅";;
    *cdnetworks*|*kinx*|*cachefly*|*edgecast*|*bunny*) echo "CDN·IX";;
    *naver*|*kakao*|*nhn*)             echo "국내 플랫폼";;
    *national*|*government*|*ministry*|*.go.kr*|*nirs*|*public*) echo "공공·정부망";;
    *univ*|*ac.kr*|*edu*|*research*)   echo "학술·연구망";;
    *broadband*|*telecom*|*kt-*|*lg\ dacom*|*skb*) echo "통신사망";;
    *)                                 echo "일반 호스팅·자체 운영";;
  esac
}

# 대상이 정말 살아 있는지, 어떤 문이 열려 있는지 훑는다.
# 포트가 여럿 열려 있으면 "서버가 죽었다" 가설은 버린다.
port_sweep() { # ip → 화면 출력
  local ip=$1 p pid open="" closed="" drop=""
  local list="21 22 25 53 80 110 143 443 465 587 993 995 3306 3389 5432 6379 8080 8443"
  rm -f "$WORK/sw."*
  for p in $list; do
    ( printf '%s' "$(tcp_probe "$ip" "$p")" > "$WORK/sw.$p" ) &
  done
  wait
  for p in $list; do
    case "$(cat "$WORK/sw.$p" 2>/dev/null)" in
      OPEN*)    open="$open $p";;
      REFUSED*) closed="$closed $p";;
      *)        drop="$drop $p";;
    esac
  done
  [ -n "$open" ]   && row "$OK" "열린 포트" "${open# }"
  [ -n "$closed" ] && row "$IN" "닫힌 포트" "${closed# }  (RST — 호스트는 응답한다)"
  [ -n "$drop" ]   && row "$IN" "무응답" "$(printf '%s' "${drop# }" | cut -c1-60)"
  if [ -z "$open$closed" ]; then
    note "어느 포트도 반응하지 않는다 — 호스트가 죽었거나 전면 차단이다"
  elif [ -z "$open" ]; then
    note "전부 RST — 호스트는 살아 있는데 아무 서비스도 안 떠 있다"
  fi
}

# 홉 목록의 소유자·역방향 이름을 한꺼번에 조회해 캐시에 채운다.
# 순서대로 물으면 홉당 1초씩 쌓여 traceroute 보다 조회가 더 오래 걸린다.
prefetch_meta() { # "ip ip ip..."
  local ip
  for ip in $(printf '%s\n' $1 | sort -u); do
    [ "$ip" = "*" ] && continue
    ( ipmeta "$ip" 1 >/dev/null 2>&1; ptr_of "$ip" >/dev/null 2>&1 ) &
  done
  wait
}

# ══════════════ L4b · 목적지 신원 — 이 IP 는 대체 무엇인가 ══════════════
# "왜 안 되는가" 만큼 "무엇에 접속하려 했는가" 도 중요하다.
# 상대가 CDN 인지 정부망인지에 따라 의심해야 할 것이 완전히 달라진다.
stage_identity() { # host port
  local h=$1 port=$2 ip
  ip=$(first_ip "$(kget "ips.$h")")
  [ -n "$ip" ] || return 0
  is_sinkhole "$ip" && return 0
  sect "L4b · 목적지 신원 — 이 IP 는 무엇인가"

  local ptr fwd asnum asname prefix cc reg alloc
  asnum=$(ipmeta "$ip" 1); prefix=$(ipmeta "$ip" 3); cc=$(ipmeta "$ip" 4)
  reg=$(ipmeta "$ip" 5);   alloc=$(ipmeta "$ip" 6);  asname=$(ipmeta "$ip" 7)

  row "$IN" "주소" "$ip  ($(ip_class "$ip"))"

  # 역방향 이름 + 정방향 재확인. 둘이 맞물려야 신뢰할 수 있는 이름이다.
  ptr=$(ptr_of "$ip")
  if [ -n "$ptr" ]; then
    # 정방향 재확인은 DNS 가 성한 곳에 물어야 의미가 있다.
    # 이 망처럼 DNS 가 가로채이면 시스템 답으로는 무조건 불일치가 나온다.
    fwd=$(doh_ips "$ptr" A "$DOH_HOST" "$DOH_IP" | tr '\n' ' ')
    [ -n "$fwd" ] || fwd=$(dig_ips "$ptr" A | tr '\n' ' ')
    case " $fwd " in
      *" $ip "*) row "$OK" "역방향 이름" "$ptr  (정방향 재확인 일치 — 믿을 수 있는 이름)";;
      "  "|" ")  row "$IN" "역방향 이름" "$ptr  (정방향 확인 불가)";;
      *)         row "$WN" "역방향 이름" "$ptr  (정방향은 ${fwd% } — 불일치. 아무나 붙일 수 있는 이름이다)";;
    esac
  else
    row "$IN" "역방향 이름" "없음 (드문 일이 아니다)"
  fi

  if [ "$asnum" = "-" ] || [ -z "$asnum" ]; then
    row "$WN" "AS" "조회 불가"
  elif [ "$asnum" = NA ]; then
    row "$NG" "AS" "없음 — 전역 BGP 에 광고되지 않는 주소다"
  else
    row "$IN" "AS" "AS$asnum  $(as_short "$asname")"
    row "$IN" "BGP 대역" "$prefix  (국가 $cc, 등록 $reg, 할당 $alloc)"
  fi

  # RIR 등록 정보 — 실제 사용 주체와 신고처가 여기 있다.
  local netname org country range abuse
  netname=$(rirfield "$ip" 'netname|NetName')
  org=$(rirfield "$ip" 'descr|org-name|orgname|OrgName|organisation')
  country=$(rirfield "$ip" 'country|Country')
  range=$(rirfield "$ip" 'inetnum|NetRange|CIDR|inet6num')
  abuse=$(rirfield "$ip" 'abuse-mailbox|OrgAbuseEmail|e-mail')
  [ -n "$netname" ] && row "$IN" "등록 대역명" "$netname${range:+   ($range)}"
  [ -n "$org" ]     && row "$IN" "사용 주체" "$org${country:+  [$country]}"
  [ -n "$abuse" ]   && row "$IN" "신고처" "$abuse"

  row "$IN" "성격" "$(ip_kind "$ip")"

  # 같은 이름이 여러 IP 로 흩어져 있으면 한 대가 죽은 것과 전체 장애가 갈린다.
  local all n
  all=$(kget "ips.$h"); n=$(printf '%s' "$all" | wc -w | tr -d ' ')
  if [ "$n" -gt 1 ]; then
    row "$IN" "서버 대수" "$n 개 주소로 분산 — 일부만 죽었을 수 있다"
  fi

  [ "$MODE" = full ] && port_sweep "$ip"
  return 0
}

# ══════════════════════════ L0 · 내 기기와 경계 ══════════════════════════
stage_local() {
  sect "L0 · 내 기기 — 경계가 어디인가"
  local gw iface ip4 mtu

  if [ "$(uname)" = Darwin ]; then
    gw=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
    iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  else
    gw=$(ip route show default 2>/dev/null | awk '/default/{print $3; exit}')
    iface=$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')
  fi
  kset gw "$gw"; kset iface "$iface"

  if [ -z "$gw" ]; then
    row "$NG" "기본 경로" "없음 — 인터넷으로 나가는 길 자체가 없다"
    finding CRIT L0 "기본 게이트웨이가 없다. 와이파이/랜 연결부터 확인한다."
  else
    if have ifconfig; then
      ip4=$(ifconfig "$iface" 2>/dev/null | awk '/inet /{print $2; exit}')
      mtu=$(ifconfig "$iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')
    else
      ip4=$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{split($2,a,"/"); print a[1]; exit}')
      mtu=$(ip link show "$iface" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')
    fi
    kset myip "$ip4"; kset mtu "$mtu"
    row "$OK" "기본 경로" "$gw  ($iface, 내 주소 ${ip4:-?}, MTU ${mtu:-?})"
    case "$ip4" in
      169.254.*) row "$NG" "주소 획득" "링크로컬 — DHCP 실패"
                 finding CRIT L0 "169.254 주소다. 공유기에서 IP 를 못 받았다.";;
    esac
    case "$mtu" in ''|1500|9000|1492) :;;
      *) row "$WN" "MTU" "$mtu — 비표준. 큰 패킷이 조용히 버려질 수 있다 (L8 참고)";;
    esac
  fi

  # VPN·터널이 끼면 "우리 집 → ISP" 라는 전제 자체가 깨진다.
  local tun
  if have ifconfig; then
    tun=$(ifconfig 2>/dev/null | awk -F: '/^(utun|tun|tap|ppp|ipsec|wg)[0-9]/{print $1}' | tr '\n' ' ')
  else
    tun=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(utun|tun|tap|ppp|ipsec|wg)[0-9]/{print $2}' | tr '\n' ' ')
  fi
  if [ -n "$tun" ]; then
    case "$iface" in
      utun*|tun*|tap*|ppp*|ipsec*)
        row "$WN" "VPN" "기본 경로가 터널($iface)을 지난다 — 아래 경로는 전부 VPN 경유다"
        finding WARN L0 "기본 경로가 VPN($iface) 이다. VPN 을 끄고 다시 재면 구간이 갈린다.";;
      *) row "$IN" "터널" "$tun (기본 경로는 아님)";;
    esac
  fi

  # 나가는 공인 IP. 사설 주소와 다르면 NAT 뒤에 있다는 뜻이고,
  # 이 IP 가 곧 상대가 보는 나다 — "내 IP 가 차단됐나" 를 따질 때의 그 IP.
  local pub
  pub=$(curl -s -m 5 --resolve one.one.one.one:443:1.1.1.1 \
        https://one.one.one.one/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/{print $2}')
  if [ -n "$pub" ]; then
    kset pubip "$pub"
    local pkind
    pkind=$(ip_class "$pub")
    if [ "$pub" = "$ip4" ]; then
      row "$IN" "공인 IP" "$pub  (NAT 없음 — 이 기기가 직접 인터넷에 있다)"
    else
      row "$IN" "공인 IP" "$pub  (NAT 뒤. 상대가 보는 나는 이 주소다)"
    fi
    case "$pkind" in
      CGNAT*) row "$WN" "CGNAT" "공인 IP 가 $pkind — 여러 가입자가 나눠 쓴다"
              finding INFO L0 "나가는 IP 가 CGNAT 대역이다. 포트 개방이 불가능하고, 남이 저지른 차단에 같이 걸릴 수 있다.";;
    esac
  else
    row "$IN" "공인 IP" "확인 불가 (외부 조회가 막혔다)"
  fi

  # 프록시가 켜져 있으면 curl 결과가 내 경로가 아니라 프록시 경로를 잰다.
  if [ "$(uname)" = Darwin ]; then
    local px
    px=$(scutil --proxy 2>/dev/null | awk '/(HTTPEnable|HTTPSEnable|ProxyAutoConfigEnable|SOCKSEnable) *: *1/{print $1}' | tr '\n' ' ')
    if [ -n "$px" ]; then
      row "$WN" "프록시" "켜짐: $px — 측정값이 프록시 경유다"
      finding WARN L0 "시스템 프록시가 켜져 있다($px). 진단 중엔 끄는 편이 낫다."
    else
      row "$OK" "프록시" "없음"
    fi
  fi
  [ -n "${http_proxy:-}${https_proxy:-}${ALL_PROXY:-}" ] && {
    row "$WN" "환경변수" "http(s)_proxy 설정됨 — curl 이 이걸 탄다"
    finding WARN L0 "http_proxy/https_proxy 환경변수가 설정돼 있다."; }
}

# ══════════════════════════ L1 · 공유기까지 ══════════════════════════
stage_link() {
  local gw; gw=$(kget gw)
  [ -n "$gw" ] || return 0
  sect "L1 · 공유기까지 — 우리 집 안은 멀쩡한가"
  local out loss rtt
  # 기본 1초 간격이면 그것만으로 3초가 넘는다. 0.2초 간격으로 줄인다
  # (0.1초 미만만 root 권한이 필요하다). 실패하면 기본 간격으로 되돌린다.
  if [ "$(uname)" = Darwin ]; then
    out=$(ping -c 5 -i 0.2 -W 800 -t 5 "$gw" 2>/dev/null) || out=$(ping -c 3 -W 800 -t 5 "$gw" 2>/dev/null)
  else
    out=$(ping -c 5 -i 0.2 -W 1 -w 5 "$gw" 2>/dev/null) || out=$(ping -c 3 -W 1 -w 5 "$gw" 2>/dev/null)
  fi
  loss=$(printf '%s' "$out" | awk '/packet loss/{for(i=1;i<=NF;i++) if($i ~ /%$/){sub(/%.*/,"",$i); sub(/\..*/,"",$i); print $i; exit}}')
  # macOS 는 "round-trip min/avg/...", Linux 는 "rtt min/avg/..." 로 시작한다.
  # 필드 번호가 하나 어긋나므로 '=' 뒤를 잘라서 읽는다.
  rtt=$(printf '%s' "$out" | awk -F'= *' '/min\/avg/{split($2,a,"/"); print a[2]" ms"; exit}')
  kset gw_loss "${loss:-100}"
  if [ -z "$loss" ] || [ "${loss:-100}" = 100 ]; then
    row "$WN" "게이트웨이" "$gw  응답 없음 (ICMP 를 막는 공유기도 있다)"
  elif [ "${loss:-0}" -gt 0 ] 2>/dev/null; then
    row "$WN" "게이트웨이" "$gw  손실 ${loss}%  ${rtt:-}  ← 무선 간섭·케이블 의심"
    finding WARN L1 "공유기까지 ${loss}% 손실. 유선으로 바꿔 다시 재 본다."
  else
    row "$OK" "게이트웨이" "$gw  손실 0%  ${rtt:-}"
  fi
}

# ══════════════════════ L2 · 인터넷 자체 (DNS 없이) ══════════════════════
# IP 리터럴로만 붙는다. 이름이 안 풀려도 인터넷이 되는지 알 수 있다.
# 여기가 다 막히면 목적지 진단은 의미가 없다.
stage_internet() {
  sect "L2 · 인터넷 자체 — DNS 없이 IP 로만"
  local up=0 tot=0 t ip port r
  for t in 1.1.1.1:443 8.8.8.8:443 9.9.9.9:443 208.67.222.222:443; do
    ip=${t%:*}; port=${t##*:}
    r=$(tcp_probe_n "$ip" "$port" 1)
    tot=$((tot+1))
    case "$r" in
      *OPEN*) up=$((up+1)); row "$OK" "$ip:$port" "$(echo "$r" | awk '{print $3" ms"}')";;
      *) row "$NG" "$ip:$port" "$(echo "$r" | awk '{print $5" ("$6")"}')";;
    esac
  done
  kset inet_up "$up"; kset inet_tot "$tot"
  if [ $up -eq 0 ]; then
    finding CRIT L2 "이름 없이 IP 로도 아무 데도 못 붙는다. 목적지가 아니라 내 회선 문제다."
    note "여기가 전부 ✘ 면 아래 결과는 전부 같은 원인이다 — 회선을 먼저 고친다."
  elif [ $up -lt $tot ]; then
    finding INFO L2 "대조군 중 일부($((tot-up))/$tot)가 막힌다. 특정 대역만 차단하는 망일 수 있다."
  fi
}

# ═════════════ L2b · 회선 대조 — 다른 회선에서는 되는가 ═════════════
# 이것이 통신사 경로 문제와 상대 망 장애를 가르는 유일한 방법이다.
# 테더링·유선 등 회선이 둘 이상 붙어 있으면 자동으로 둘 다 재 본다.
usable_ifaces() { # → "iface,ip iface,ip ..."
  if have ifconfig; then
    ifconfig 2>/dev/null | awk '
      /^[a-z]/ { i=$1; sub(/:$/,"",i) }
      /inet / && $2 !~ /^(127\.|169\.254\.)/ { print i","$2 }'
  else
    ip -o -4 addr show 2>/dev/null | awk '$4 !~ /^(127\.|169\.254\.)/ {split($4,a,"/"); print $2","a[1]}'
  fi
}

stage_multipath() { # host port
  local h=$1 port=$2 ips ip list n
  ips=$(kget "ips.$h"); ip=$(first_ip "$ips")
  [ -n "$ip" ] || return 0
  is_sinkhole "$ip" && return 0
  list=$(usable_ifaces)
  n=$(printf '%s\n' "$list" | grep -c . )
  [ "$n" -gt 1 ] || return 0

  sect "L2b · 회선 대조 — 다른 회선에서는 되는가"

  # 출발지 주소를 묶는다고 라우팅이 따라오는 것은 아니다.
  # macOS 는 scoped routing 으로 바인딩한 인터페이스로 내보내지만,
  # Linux 는 목적지 기준으로만 경로를 고르므로 엉뚱한 회선으로 나갈 수 있다.
  # 그 경우 결과가 거짓이 되므로, 실제 나가는 인터페이스를 확인해서 걸러 낸다.
  local e ifc sip r okc=0 ngc=0 dev
  for e in $list; do
    ifc=${e%,*}; sip=${e#*,}
    if [ "$(uname)" != Darwin ] && have ip; then
      dev=$(ip route get "$ip" from "$sip" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
      if [ -n "$dev" ] && [ "$dev" != "$ifc" ]; then
        row "$WN" "$ifc" "출발지만 묶으면 실제로는 $dev 로 나간다 — 이 회선 단독 검사 불가"
        note "정확히 재려면 정책 라우팅(ip rule)이나 별도 네임스페이스가 필요하다"
        continue
      fi
    fi
    r=$(tcp_probe_n "$ip" "$port" 1 "$sip")
    case "$r" in
      *OPEN*) okc=$((okc+1)); row "$OK" "$ifc" "$sip → $ip:$port  열림  $(echo "$r" | awk '{print $3}')ms";;
      *)      ngc=$((ngc+1)); row "$NG" "$ifc" "$sip → $ip:$port  $(echo "$r" | awk '{print $5}')";;
    esac
  done
  if [ $okc -gt 0 ] && [ $ngc -gt 0 ]; then
    finding CRIT L2b "회선에 따라 결과가 갈린다 — 상대 서버가 아니라 안 되는 쪽 회선(통신사)의 경로 문제다."
    note "이게 결정적이다. 상대가 죽었다면 어느 회선으로 가도 똑같이 안 된다"
  elif [ $okc -gt 1 ]; then
    row "$OK" "판정" "회선 $okc 개 모두 열린다 — 지금 이 순간은 정상이다"
    note "간헐 장애가 의심되면 -r 과 -i 로 시간 간격을 두고 다시 본다"
  elif [ $ngc -gt 0 ] && [ $okc -eq 0 ]; then
    finding INFO L2b "$ngc 개 회선 전부에서 안 된다 — 내 회선 문제가 아니라 상대 또는 공통 경로 문제다."
  fi
}

# ══════════════════════════ L3 · DNS ══════════════════════════
# 시스템·공용 DNS·DoH 를 모두 물어보고 답을 대조한다.
# DoH 는 IP 리터럴로 붙기 때문에 53번 가로채기를 우회한다 → 이게 "진짜 답" 이다.
# 응답 코드까지 본다. 답이 없는 것과 "그런 이름 없다" 는 원인이 전혀 다르다.
dns_rcode() { # name type [server] → NOERROR | NXDOMAIN | SERVFAIL | REFUSED | NOANSWER
  local out
  out=$(dig +tries=1 +time=2 +noall +comments "$2" "$1" ${3:+@$3} 2>/dev/null)
  [ -n "$out" ] || { echo TIMEOUT; return; }
  printf '%s' "$out" | awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:"){s=$(i+1); sub(/,/,"",s); print s; exit}}' \
    | grep -q . && printf '%s' "$out" | awk '/status:/{for(i=1;i<=NF;i++) if($i=="status:"){s=$(i+1); sub(/,/,"",s); print s; exit}}' \
    || echo TIMEOUT
}

dig_ips() { # name type [server]
  local name=$1 type=$2 srv=${3:-}
  dig +tries=1 +time=2 +short "$type" "$name" ${srv:+@$srv} 2>/dev/null \
    | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+:[0-9a-fA-F:]*$' | sort -u
}

# DoH 응답을 캐시해 두고 주소와 상태(Status)를 따로 꺼내 쓴다.
# "답이 없다" 와 "그런 이름이 없다" 를 여기서도 갈라야 한다.
doh_fetch() { # name type dohhost dohip → 캐시 파일 경로
  local name=$1 type=$2 h=$3 sip=$4 f
  f="$WORK/doh.$(printf '%s.%s.%s' "$name" "$type" "$h" | tr -c 'A-Za-z0-9._-' '_')"
  [ -f "$f" ] || curl -s -m "$TMO" --resolve "$h:443:$sip" \
      -H 'accept: application/dns-json' \
      "https://$h/dns-query?name=$name&type=$type" > "$f" 2>/dev/null
  printf '%s' "$f"
}

doh_status() { # name type dohhost dohip → NOERROR|NXDOMAIN|... 또는 빈 문자열
  local f code
  f=$(doh_fetch "$1" "$2" "$3" "$4")
  [ -s "$f" ] || return 1
  code=$(tr ',' '\n' < "$f" | awk -F: '/"Status"/{gsub(/[^0-9]/,"",$2); print $2; exit}')
  case "$code" in
    0) echo NOERROR;; 2) echo SERVFAIL;; 3) echo NXDOMAIN;; 5) echo REFUSED;;
    "") return 1;; *) echo "RCODE$code";;
  esac
}

doh_ips() { # name type dohhost dohip
  local name=$1 type=$2 h=$3 sip=$4 body f
  f=$(doh_fetch "$name" "$type" "$h" "$sip")
  [ -s "$f" ] || return 1
  body=$(cat "$f")
  if [ "$HAVE_JQ" = 1 ]; then
    printf '%s' "$body" | jq -r '.Answer[]? | select(.type==1 or .type==28) | .data' 2>/dev/null | sort -u
  else
    printf '%s' "$body" | tr ',' '\n' | awk -F'"' '/"data"/{print $4}' \
      | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$|:' | sort -u
  fi
}

stage_dns() { # host
  local h=$1
  sect "L3 · DNS — 이름이 어떤 IP 로 바뀌는가"

  # 이미 IP 를 넣었으면 DNS 단계는 통째로 건너뛴다.
  # (IPv6 리터럴은 a~f 를 포함하므로 "글자가 있으면 호스트명" 으로 판단하면 안 된다.)
  if is_ip_literal "$h"; then
    kset "ips.$h" "$h"; kset "dns.$h" skip
    row "$IN" "생략" "$h 는 IP 리터럴 — 이름 해석이 필요 없다"; return 0
  fi

  local sys pub1 pub2 truth truth2 t0 t1 ms
  t0=$(now_ms)
  sys=$(dig_ips "$h" A)
  t1=$(now_ms)
  ms=$(( t1 - t0 )); [ "$ms" -lt 0 ] 2>/dev/null && ms=0
  pub1=$(dig_ips "$h" A 1.1.1.1)
  pub2=$(dig_ips "$h" A 8.8.8.8)
  truth=$(doh_ips "$h" A "$DOH_HOST" "$DOH_IP")
  [ -n "$truth" ] || truth2=$(doh_ips "$h" A "$DOH2_HOST" "$DOH2_IP")
  [ -n "$truth" ] || truth=$truth2

  local v6=""
  [ "$IPV" != 4 ] && v6=$(dig_ips "$h" AAAA)

  local s_sys s_p1 s_p2 s_tr
  s_sys=$(printf '%s' "$sys"  | tr '\n' ' '); s_sys=${s_sys% }
  s_p1=$(printf '%s' "$pub1"  | tr '\n' ' '); s_p1=${s_p1% }
  s_p2=$(printf '%s' "$pub2"  | tr '\n' ' '); s_p2=${s_p2% }
  s_tr=$(printf '%s' "$truth" | tr '\n' ' '); s_tr=${s_tr% }

  local rc rc1
  rc=$(dns_rcode "$h" A)
  if [ -z "$s_sys" ]; then
    case "$rc" in
      NXDOMAIN) row "$NG" "시스템" "NXDOMAIN — 그런 이름이 없다고 한다  (${ms}ms)";;
      SERVFAIL) row "$NG" "시스템" "SERVFAIL — DNS 서버가 답을 못 만든다 (DNSSEC 실패·상위 장애)  (${ms}ms)";;
      REFUSED)  row "$NG" "시스템" "REFUSED — DNS 서버가 질의를 거부했다  (${ms}ms)";;
      TIMEOUT)  row "$NG" "시스템" "무응답 — DNS 서버에 닿지 못한다  (${ms}ms)";;
      *)        row "$NG" "시스템" "$rc — 주소 레코드가 없다  (${ms}ms)";;
    esac
  else
    row "$OK" "시스템" "$s_sys  (${ms}ms, 서버 $(dns_servers | sed 's/ $//'))"
  fi
  if [ -n "$s_p1" ]; then row "$IN" "@1.1.1.1" "$s_p1"
  else rc1=$(dns_rcode "$h" A 1.1.1.1); row "$WN" "@1.1.1.1" "답 없음 ($rc1)"; fi
  [ -n "$s_p2" ] && row "$IN" "@8.8.8.8" "$s_p2" || row "$WN" "@8.8.8.8" "답 없음"
  if [ -n "$s_tr" ]; then
    row "$IN" "DoH(진짜값)" "$s_tr"
  else
    local dst
    dst=$(doh_status "$h" A "$DOH_HOST" "$DOH_IP" 2>/dev/null)
    case "$dst" in
      NXDOMAIN) row "$IN" "DoH(진짜값)" "NXDOMAIN — 바깥에서도 그런 이름은 없다";;
      "")       row "$WN" "DoH(진짜값)" "확인 불가 — DoH 가 막혔거나 인터넷이 안 된다";;
      *)        row "$WN" "DoH(진짜값)" "$dst — 주소 레코드가 없다";;
    esac
  fi
  if [ -n "$v6" ]; then
    if is_sinkhole "$(first_ip "$v6")"; then
      row "$WN" "AAAA" "$(printf '%s' "$v6" | tr '\n' ' ') — v6 도 싱크홀이다"
    else
      row "$IN" "AAAA" "$(printf '%s' "$v6" | tr '\n' ' ')"
    fi
  fi

  # ── 판정 ──
  local first; first=$(first_ip "$sys")
  if [ -n "$first" ] && is_sinkhole "$first"; then
    row "$NG" "판정" "싱크홀 — $first 로 답한다. 누군가 이 이름을 죽였다"
    finding CRIT L3 "$h → $first (싱크홀). 공유기·보안SW·회사 DNS 정책이 이 이름을 막고 있다."
  elif [ -n "$first" ] && is_private "$first" ; then
    row "$WN" "판정" "사설 IP($first) 로 답한다 — 내부 DNS 이거나 가로채기"
    finding WARN L3 "$h 가 사설 IP 로 해석된다. 사내망/공유기 DNS 를 보고 있다."
  fi

  # 답이 다르다고 곧바로 조작은 아니다. CDN·GSLB 는 묻는 위치에 따라 다른 IP 를 준다.
  # 갈라 내는 기준은 IP 가 아니라 소유자(AS)다. 같은 AS 면 그냥 다른 서버, 다른 AS 면 조작이다.
  local hijack=0
  if [ -n "$s_tr" ] && [ -n "$s_sys" ] && [ "$s_sys" != "$s_tr" ]; then
    local overlap=0 x
    for x in $s_sys; do case " $s_tr " in *" $x "*) overlap=1;; esac; done
    if [ $overlap -eq 0 ]; then
      local as_sys as_tr
      as_sys=$(asn_of "$(printf '%s' "$s_sys" | awk '{print $1}')"); as_sys=${as_sys%% *}
      as_tr=$(asn_of  "$(printf '%s' "$s_tr"  | awk '{print $1}')"); as_tr=${as_tr%% *}
      if [ "$as_sys" = "$as_tr" ] && [ "$as_sys" != "-" ]; then
        row "$IN" "답 차이" "시스템과 DoH 가 다른 IP — 같은 AS($as_sys) 다. CDN/GSLB 이지 조작이 아니다"
      else
        hijack=1
        row "$NG" "가로채기" "시스템 답과 실제 답의 소유자가 다르다 (AS $as_sys vs AS $as_tr)"
        note "시스템=$s_sys"
        note "진짜  =$s_tr"
        finding CRIT L3 "DNS 응답이 조작되고 있다. 시스템은 $s_sys(AS$as_sys), 실제는 $s_tr(AS$as_tr) 이다."
      fi
    fi
  fi
  if [ $hijack = 1 ] && [ -n "$s_p1" ] && [ "$s_p1" = "$s_sys" ]; then
    row "$NG" "투명 가로채기" "@1.1.1.1 로 물어도 같은 답 — 53번 요청이 통째로 가로채인다"
    finding CRIT L3 "평문 DNS(53) 가 투명 프록시로 가로채인다. DNS 서버를 바꿔도 소용없다."
  fi

  # CNAME 이 엉뚱한 이름으로 바뀌는 방식의 개입은 IP 비교로는 안 잡힌다.
  local cn
  cn=$(dig +tries=1 +time=2 +noall +answer "$h" 2>/dev/null | awk '$4=="CNAME"{print $5}' | tr '\n' ' ')
  if [ -n "$cn" ]; then
    row "$IN" "CNAME" "${cn% }"
    case "$cn" in
      *forcesafesearch*|*restrict*|*sinkhole*|*block*|*warning*|*filter*)
        row "$WN" "이름 갈아치움" "정책 CNAME 이 끼어 있다 — 이 망이 이름을 갈아치운다"
        finding WARN L3 "$h 가 ${cn% } 로 CNAME 되어 있다. 망 사업자·공유기의 필터링 정책이다.";;
    esac
  fi

  # -6 을 줬으면 실제로 v6 주소를 물고 아래 단계로 내려간다. 안 그러면 옵션이 거짓말이 된다.
  local use
  if [ "$IPV" = 6 ]; then
    use=$(printf '%s' "$v6" | tr '\n' ' '); use=${use% }
    [ -n "$use" ] || { row "$NG" "IPv6" "AAAA 레코드가 없다 — -6 로는 진단할 수 없다"
                       finding CRIT L3 "$h 에 AAAA 레코드가 없다. IPv6 로는 접속 자체가 불가능하다."
                       kset "ips.$h" ""; return 1; }
  else
    use=$s_sys
  fi
  [ -n "$use" ] || use=$s_tr
  if [ -z "$use" ]; then
    # 여기서 갈라야 한다. "없는 이름" 과 "막힌 이름" 은 고치는 방법이 정반대다.
    if [ "$rc" = NXDOMAIN ] && [ -z "$s_tr" ]; then
      row "$NG" "결론" "이 이름은 존재하지 않는다 — 공용 DNS 도 DoH 도 없다고 한다"
      finding CRIT L3b "$h 이라는 이름이 실제로 없다. 오타이거나 도메인이 등록되지 않았거나 만료됐다."
    elif [ "$rc" = NXDOMAIN ] && [ -n "$s_tr" ]; then
      row "$NG" "결론" "시스템만 없다고 한다 — NXDOMAIN 주입(차단 기법)이다"
      finding CRIT L3 "$h 에 대해 시스템 DNS 만 NXDOMAIN 을 준다. 실제로는 $s_tr 로 존재한다 — 이름을 죽이는 차단이다."
    elif [ "$rc" = SERVFAIL ]; then
      row "$NG" "결론" "SERVFAIL — 권위 서버 장애이거나 DNSSEC 검증 실패다"
      finding CRIT L3b "$h 가 SERVFAIL 이다. 도메인 쪽 DNS 장애이거나 DNSSEC 서명이 깨졌다."
    else
      row "$NG" "결론" "이름을 IP 로 바꿀 수 없다 — 아래 단계는 진행 불가"
      finding CRIT L3 "$h 이름 해석 실패($rc). DNS 서버 도달성부터 본다."
    fi
    kset "ips.$h" ""; return 1
  fi
  kset "ips.$h" "$use"
  kset "truth.$h" "$s_tr"
  return 0
}

# 등록 가능한 도메인만 남긴다. co.kr / go.kr / com.au 처럼 2단계 TLD 를 감안한다.
reg_domain() { # a.b.example.co.kr → example.co.kr
  printf '%s' "$1" | awk -F. '{
    n = NF
    if (n < 2) { print; exit }
    two = $(n-1) "." $n
    if (two ~ /^(co|ne|or|go|re|pe|ac|hs|ms|es|kg|sc)\.kr$/ ||
        two ~ /^(co|net|org|gov|ac|edu)\.(uk|jp|au|nz|za|in|br|cn|kr)$/) {
      if (n >= 3) { print $(n-2) "." two; exit }
    }
    print two
  }'
}

# ══════ L3b · 이름 자체의 상태 — 도메인·권위 서버 ══════
# 캐시된 답만 보면 "도메인이 만료됐다"·"등록기관이 정지시켰다" 를 못 본다.
stage_domain() { # host
  local h=$1 d
  is_ip_literal "$h" && return 0
  [ "$MODE" = quick ] && return 0
  d=$(reg_domain "$h")
  sect "L3b · 이름의 상태 — 도메인과 권위 서버"

  # 등록 정보. 만료·정지 상태면 여기서 끝난다.
  local w exp reg st
  w=$(runto 9 whois "$d" 2>/dev/null)
  exp=$(printf '%s' "$w" | awk -F: 'BEGIN{IGNORECASE=1} /(Registry Expiry Date|Expiration Date|expires|paid-till)/ {sub(/^[^:]*: */,""); gsub(/^ +| +$/,""); if($0!=""){print; exit}}')
  reg=$(printf '%s' "$w" | awk -F: 'BEGIN{IGNORECASE=1} /^ *Registrar:/ {sub(/^[^:]*: */,""); gsub(/^ +| +$/,""); if($0!=""){print; exit}}')
  st=$(printf '%s' "$w" | awk 'BEGIN{IGNORECASE=1} /(Domain Status|^status:)/ {sub(/^[^:]*: */,""); gsub(/ +https:.*/,""); gsub(/^ +| +$/,""); if($0!="") print}' | sort -u | tr '\n' ' ')

  [ -n "$reg" ] && row "$IN" "등록기관" "$reg"
  if [ -n "$exp" ]; then
    row "$IN" "만료일" "$exp"
    # 만료가 지났거나 코앞이면 그 자체가 원인이다.
    local ed today
    ed=$(printf '%s' "$exp" | sed -n 's/.*\([0-9]\{4\}\)-\([0-9][0-9]\)-\([0-9][0-9]\).*/\1\2\3/p')
    today=$(date +%Y%m%d)
    if [ -n "$ed" ] && [ "$ed" -lt "$today" ] 2>/dev/null; then
      row "$NG" "만료" "이미 지났다 — 이름이 죽는 원인이다"
      finding CRIT L3 "$d 도메인이 $exp 에 만료됐다. 접속 실패의 원인이 이것일 수 있다."
    fi
  fi
  case "$st" in
    *[Hh]old*|*pendingDelete*|*redemptionPeriod*|*[Ss]uspend*)
      row "$NG" "등록 상태" "$st"
      finding CRIT L3 "$d 가 정지·삭제 대기 상태다($st). 등록기관이 이름을 끊은 것이다.";;
    "") :;;
    *) row "$IN" "등록 상태" "$(printf '%s' "$st" | cut -c1-70)";;
  esac

  # 권위 서버에 직접 물어 캐시와 대조한다. 다르면 캐시가 오래됐거나 오염된 것이다.
  local ns first_ns auth cached
  ns=$(dig +tries=1 +time=2 +short NS "$d" 2>/dev/null | head -3 | tr '\n' ' ')
  if [ -n "$ns" ]; then
    row "$IN" "권위 서버" "${ns% }"
    first_ns=$(printf '%s' "$ns" | awk '{print $1}')
    auth=$(dig_ips "$h" A "$first_ns" | tr '\n' ' ')
    cached=$(kget "ips.$h")
    if [ -n "$auth" ]; then
      local hit=0 x
      for x in $auth; do case " $cached " in *" $x "*) hit=1;; esac; done
      if [ $hit = 1 ]; then
        row "$OK" "권위 답 대조" "캐시와 일치 (${auth% })"
      else
        row "$WN" "권위 답 대조" "권위=${auth% }  캐시=$cached — 다르다"
        finding WARN L3 "권위 서버의 답과 지금 쓰는 답이 다르다. 캐시가 낡았거나 조작됐다."
      fi
    fi
  else
    row "$WN" "권위 서버" "NS 레코드를 못 받았다 — 위임이 끊겼을 수 있다"
  fi

  # TTL 이 아주 짧으면 GSLB·장애 조치 중이라는 뜻이다.
  local ttl
  ttl=$(dig +tries=1 +time=2 +noall +answer A "$h" 2>/dev/null | awk '$4=="A"{print $2; exit}')
  if [ -n "$ttl" ]; then
    if [ "$ttl" -le 60 ] 2>/dev/null; then
      row "$IN" "TTL" "${ttl}초 — 매우 짧다. 장애 조치·GSLB 로 답이 수시로 바뀐다"
    else
      row "$IN" "TTL" "${ttl}초"
    fi
  fi
}

dns_servers() {
  if [ "$(uname)" = Darwin ]; then
    scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3}' | sort -u | tr '\n' ' '
  else
    awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | tr '\n' ' '
  fi
}

# ══════════════════════════ L4 · TCP ══════════════════════════
# 해석된 모든 IP × 요청 포트. 실패 이유(드롭/RST/도달불가)를 구분한다.
# 여기서 막히면 TLS·HTTP·API 키는 볼 필요조차 없다.
stage_tcp() { # host port
  local h=$1 port=$2 ips ip r st ok mn av mx why any=0 alldrop=1
  ips=$(kget "ips.$h")
  [ -n "$ips" ] || return 1
  sect "L4 · TCP $port — 3-way 가 되는가  (${REPEAT}회)"

  # 싱크홀 주소는 걸러 낸다. 0.0.0.0 으로 connect 하면 내 컴퓨터에 붙는다 —
  # 그 결과를 목적지 상태로 읽으면 완전히 헛짚는다.
  local real=""
  for ip in $ips; do
    if is_sinkhole "$ip"; then
      row "$NG" "$ip" "싱크홀 주소 — 붙어 볼 대상이 아니다 (여기 붙으면 내 컴퓨터다)"
    else
      real="$real $ip"
    fi
  done
  if [ -z "${real# }" ]; then
    note "이름이 죽은 주소로 해석됐다 — L3 이 원인이다."
    # DoH 로 알아낸 진짜 IP 로는 붙는가? 이걸 봐야 "이름만 죽인 것" 인지
    # "대상 자체가 막힌 것" 인지 갈린다. 고치는 방법이 전혀 다르다.
    local tip tr_ok=0 tr_n=0 rr
    for tip in $(kget "truth.$h"); do
      is_sinkhole "$tip" && continue
      tr_n=$((tr_n+1))
      rr=$(tcp_probe_n "$tip" "$port" 1)
      case "$rr" in
        *OPEN*) tr_ok=$((tr_ok+1))
                row "$OK" "  ↳ 진짜 IP" "$tip:$port 열림  ($(as_short "$(ipmeta "$tip" 7)"))";;
        *)      row "$NG" "  ↳ 진짜 IP" "$tip:$port $(echo "$rr" | awk '{print $5}')";;
      esac
    done
    if [ $tr_n -gt 0 ] && [ $tr_ok -gt 0 ]; then
      finding CRIT L3 "이름만 죽어 있다. 진짜 IP($(first_ip "$(kget "truth.$h")"))로는 $port 가 열린다 — 대상 서버는 멀쩡하고 DNS 만 막혔다."
      note "대상은 살아 있다. DNS 를 고치거나 hosts 로 우회하면 접속된다"
    elif [ $tr_n -gt 0 ]; then
      finding CRIT L3 "이름도 죽었고 진짜 IP 로도 붙지 않는다 — DNS 차단과 경로 차단이 겹쳐 있다."
    fi
    kset "tcp.$h.$port" 0; kset "tcp.$h.alldrop" 0
    return 1
  fi
  ips=${real# }

  # 애초에 인터넷으로 갈 수 없는 주소인지 먼저 본다.
  # 여기 걸리면 원인은 경로가 아니라 주소 자체다 — 통신사에 문의할 일이 아니다.
  for ip in $ips; do
    case "$(ip_class "$ip")" in
      문서용*|벤치마크*|예약*|IETF*|멀티캐스트*)
        row "$NG" "$ip" "$(ip_class "$ip") 대역 — 인터넷에서 쓸 수 없는 주소다"
        finding CRIT L4 "$ip 는 $(ip_class "$ip") 대역이다. 실제 서비스에 쓰이지 않는 주소이므로 설정이나 DNS 답이 잘못됐다."
        continue;;
      링크로컬*)
        row "$NG" "$ip" "링크로컬 — 같은 랜 안에서만 쓰는 주소다"
        finding CRIT L4 "$ip 는 링크로컬 주소다. 인터넷 목적지가 될 수 없다."
        continue;;
    esac
    case "$(asn_of "$ip")" in
      NA\ *) row "$NG" "$ip" "전역 라우팅에 없다 — 인터넷 어디에도 광고되지 않는 주소다"
             finding CRIT L4 "$ip 는 BGP 로 광고되지 않는 주소다. 막힌 게 아니라 갈 곳이 없다 — DNS 답이나 설정된 주소가 잘못됐다.";;
    esac
  done

  for ip in $ips; do
    r=$(tcp_probe_n "$ip" "$port")
    ok=$(echo "$r"  | awk '{print $1}')
    mn=$(echo "$r"  | awk '{print $2}')
    av=$(echo "$r"  | awk '{print $3}')
    mx=$(echo "$r"  | awk '{print $4}')
    st=$(echo "$r"  | awk '{print $5}')
    why=$(echo "$r" | awk '{print $6}')
    case "$st" in
      OPEN)
        any=1; alldrop=0
        if [ "${ok%%/*}" = "${ok##*/}" ]; then
          row "$OK" "$ip" "$ok 성공  ${av}ms (${mn}–${mx})  $(asn_of "$ip")"
        else
          row "$WN" "$ip" "$ok 성공 — 간헐  ${av}ms (${mn}–${mx})  $(asn_of "$ip")"
          finding WARN L4 "$(hp "$h" "$ip"):$port 이 $ok 만 붙는다. 간헐 장애·부하분산 중 일부 노드 불량."
        fi;;
      REFUSED)
        alldrop=0
        row "$NG" "$ip" "$ok  RST 수신 — 호스트는 살아 있고 $port 만 닫혔다"
        finding CRIT L4 "$(hp "$h" "$ip"):$port 이 RST 로 거절된다. 서버가 그 포트를 안 열었거나 서비스가 죽었다.";;
      UNREACH)
        alldrop=0
        row "$NG" "$ip" "$ok  ICMP 도달불가 — 라우터가 길이 없다고 알려 준다"
        finding CRIT L4 "$(hp "$h" "$ip"):$port 로 가는 경로가 없다(ICMP unreachable). 라우팅 문제다.";;
      RESET)
        alldrop=0
        row "$NG" "$ip" "$ok  붙자마자 끊김 — 중간 장비가 끼어들었을 가능성"
        finding CRIT L4 "$(hp "$h" "$ip"):$port 이 연결 직후 RST 로 끊긴다. 검열·IPS 장비의 전형이다.";;
      *)
        row "$NG" "$ip" "$ok  무응답(드롭) ${TMO}s  $(asn_of "$ip")"
        finding CRIT L4 "$(hp "$h" "$ip"):$port 가 조용히 버려진다. 방화벽 DROP·널라우팅·경로 단절이다.";;
    esac
  done
  kset "tcp.$h.$port" "$any"; kset "tcpok.$h" "$any"

  # 열림/막힘만으로는 "호스트가 죽었나, 그 포트만 막혔나" 를 못 가른다 → 다른 포트를 본다.
  if [ $any -eq 0 ]; then
    local alt p rr
    case "$port" in 443) alt="80 22";; 80) alt="443 22";; *) alt="443 80";; esac
    [ "$MODE" = full ] && alt="$alt 53 8080 8443"
    local first; first=$(first_ip "$ips")
    for p in $alt; do
      rr=$(tcp_probe_n "$first" "$p" 1)
      case "$rr" in
        *OPEN*)  row "$WN" "  ↳ :$p" "열림 — 호스트는 살아 있다. $port 만 막힌 것";;
        *REFUSED*) row "$IN" "  ↳ :$p" "RST — 호스트는 응답한다";;
        *)       row "$IN" "  ↳ :$p" "무응답";;
      esac
      case "$rr" in *OPEN*|*REFUSED*)
        finding INFO L4 "$first 의 $p 번은 반응한다 → 호스트는 살아 있고 $port 만 선택적으로 막혔다."
        alldrop=0;; esac
    done
  fi
  kset "tcp.$h.alldrop" "$alldrop"
  [ $any -eq 1 ]
}

# ══════════════════════════ L5 · TLS ══════════════════════════
# 인증서·프로토콜·SNI. SNI 차단은 "TCP 는 되는데 TLS 만 안 되는" 형태로 나타난다.
stage_tls() { # host port
  local h=$1 port=$2
  [ "$HAVE_SSL" = 1 ] || { row "$IN" "TLS" "openssl 없음 — 생략"; return 0; }
  case "$port" in 443|8443|993|995|465|587|853) :;; *) [ "$MODE" = full ] || return 0;; esac
  sect "L5 · TLS — 인증서·협상"

  local out ver cipher vrf subj iss nb na alpn
  out=$(printf 'Q\n' | runto $((TMO+3)) openssl s_client -connect "$h:$port" -servername "$h" \
        -alpn h2,http/1.1 2>&1)
  ver=$(printf '%s' "$out"    | awk -F'Protocol *: *' '/Protocol *:/{print $2; exit}')
  [ -n "$ver" ] || ver=$(printf '%s' "$out" | awk '/^New, TLS/{print $2; exit}' | tr -d ',')
  cipher=$(printf '%s' "$out" | awk -F'Cipher *is *' '/Cipher *is/{print $2; exit}')
  vrf=$(printf '%s' "$out"    | awk -F'Verify return code: *' '/Verify return code/{print $2; exit}')
  subj=$(printf '%s' "$out"   | awk -F'subject=' '/^subject=/{print $2; exit}')
  iss=$(printf '%s' "$out"    | awk -F'issuer=' '/^issuer=/{print $2; exit}')
  alpn=$(printf '%s' "$out"   | awk -F': *' '/^ALPN protocol/{print $2; exit}')

  if ! printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE'; then
    row "$NG" "핸드셰이크" "실패 — $(printf '%s' "$out" | grep -m1 -E 'error|alert|refused|timeout' | cut -c1-80)"
    finding CRIT L5 "$h:$port TLS 핸드셰이크가 실패한다. TCP 는 되는데 여기서 막힌다면 SNI 차단·중간자·구형 TLS 다."
    # SNI 를 빼고 다시 — 이게 되면 이름을 보고 막는 장비가 있다는 뜻이다.
    local nosni
    nosni=$(printf 'Q\n' | runto $((TMO+3)) openssl s_client -connect "$h:$port" -noservername 2>&1)
    if printf '%s' "$nosni" | grep -q 'BEGIN CERTIFICATE'; then
      row "$NG" "SNI 차단" "SNI 를 빼면 핸드셰이크가 된다 → 호스트명을 보고 끊는다"
      finding CRIT L5 "SNI 기반 차단이 확실하다. 중간 장비가 ClientHello 의 호스트명을 읽고 끊는다."
    fi
    return 1
  fi

  row "$OK" "핸드셰이크" "${ver:-?}  ${cipher:-?}${alpn:+  ALPN=$alpn}"
  case "$ver" in TLSv1|TLSv1.1|SSLv3) row "$WN" "버전" "$ver — 곧 거부될 구형 프로토콜";; esac

  case "$vrf" in
    0*|"0 (ok)") row "$OK" "검증" "0 (ok)";;
    "") row "$IN" "검증" "확인 불가";;
    *)  row "$NG" "검증" "$vrf"
        finding CRIT L5 "인증서 검증 실패: $vrf";;
  esac

  # 인증서 본체 — 만료·이름 일치·발급자
  local pem="$WORK/cert.pem"
  printf '%s' "$out" | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > "$pem"
  if [ -s "$pem" ]; then
    na=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    nb=$(openssl x509 -in "$pem" -noout -startdate 2>/dev/null | cut -d= -f2)
    local left=""
    if openssl x509 -in "$pem" -noout -checkend 0 >/dev/null 2>&1; then
      openssl x509 -in "$pem" -noout -checkend 1209600 >/dev/null 2>&1 \
        && left="유효" || { left="14일 내 만료"; finding WARN L5 "$h 인증서가 2주 안에 만료된다 ($na)."; }
    else
      left="만료됨"; finding CRIT L5 "$h 인증서가 이미 만료됐다 ($na)."
    fi
    row "$([ "$left" = 유효 ] && echo "$OK" || echo "$NG")" "유효기간" "$nb ~ $na  ($left)"
    row "$IN" "발급자" "$(printf '%s' "$iss" | sed 's/^ *//' | cut -c1-70)"
    # IP 로 붙었으면 이름이 아니라 IP 가 인증서에 있는지를 봐야 한다.
    # 이름으로 검사하면 정상 서버도 전부 실패로 나온다.
    local ckopt=-checkhost
    is_ip_literal "$h" && ckopt=-checkip
    if openssl x509 -in "$pem" -noout "$ckopt" "$h" >/dev/null 2>&1; then
      row "$OK" "이름 일치" "$h 가 인증서에 있다"
    elif [ "$ckopt" = -checkip ]; then
      row "$IN" "이름 일치" "$h 는 인증서에 없다 — IP 로 붙었으니 정상이다 (이름으로 붙어야 검증된다)"
    else
      row "$NG" "이름 일치" "$h 가 인증서에 없다 — 잘못된 서버이거나 중간자"
      finding CRIT L5 "인증서의 이름이 $h 와 다르다. 중간자 또는 잘못된 vhost 다."
    fi
    # 인증서의 SAN 은 "이 서버가 어떤 이름들을 담당하는가" 를 그대로 보여 준다.
    local san
    san=$(openssl x509 -in "$pem" -noout -ext subjectAltName 2>/dev/null \
          | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ' | paste -sd' ' - 2>/dev/null)
    if [ -n "$san" ]; then
      local sn; sn=$(printf '%s' "$san" | wc -w | tr -d ' ')
      row "$IN" "인증서 이름" "$(printf '%s' "$san" | cut -c1-64)$([ "$sn" -gt 6 ] && echo " …($sn개)")"
    fi

    # TLS 가로채기 판정. "내 목록에 없는 CA = 수상함" 으로 하면 멀쩡한 CA 를
    # 계속 오인한다. 대신 (a) 검증 실패거나 (b) 알려진 가로채기 제품 이름일 때만 잡는다.
    local il; il=$(printf '%s' "$iss" | tr 'A-Z' 'a-z')
    case "$il" in
      *fortinet*|*fortigate*|*palo\ alto*|*zscaler*|*netskope*|*blue\ coat*|*bluecoat*|\
      *symantec\ web*|*sophos*|*kaspersky*|*bitdefender*|*eset*|*avast*|*avg\ *|\
      *mcafee*|*trend\ micro*|*websense*|*forcepoint*|*checkpoint*|*check\ point*|\
      *umbrella*|*mitmproxy*|*charles*|*fiddler*|*burp*)
        row "$NG" "가로채기 장비" "발급자가 TLS 검사 제품이다 — 이 연결은 중간에서 열려 읽히고 있다"
        finding CRIT L5 "TLS 가 중간에서 복호화되고 있다(발급자: $iss). 회사 방화벽·백신의 SSL 검사 기능이다.";;
      *)
        case "$vrf" in
          0*|"") :;;
          *) row "$WN" "발급자" "검증도 실패했다 — 발급자를 확인하라: $(printf '%s' "$iss" | cut -c1-60)";;
        esac;;
    esac
  fi
  return 0
}

# ══════════════════════════ L6 · HTTP ══════════════════════════
# 여기까지 왔으면 망은 정상이다. 남은 실패는 전부 애플리케이션 문제다.
stage_http() { # host port
  local h=$1 port=$2 scheme=https
  case "$port" in 80|8080|8000) scheme=http;; 443|8443) scheme=https;; *) [ "$MODE" = full ] || return 0;; esac
  sect "L6 · HTTP — 서버가 대답을 하는가"

  local hdr="$WORK/hdr.txt" body="$WORK/body.bin" w
  w=$(curl -sS -m $((TMO*3)) -o "$body" -D "$hdr" -L --max-redirs 5 \
      -A "netcheck/$VERSION" \
      -w '%{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total} %{http_code} %{num_redirects} %{size_download} %{http_version} %{remote_ip}' \
      "$scheme://$h:$port/" 2>"$WORK/curlerr")
  local rc=$?
  if [ $rc -ne 0 ] && [ -z "$w" ]; then
    row "$NG" "요청" "실패 — $(cut -c1-90 < "$WORK/curlerr")"
    finding CRIT L6 "$scheme://$h:$port 요청 실패 (curl $rc)."
    return 1
  fi

  set -- $w
  local dns=$1 con=$2 tls=$3 ttfb=$4 tot=$5 code=$6 nred=$7 size=$8 hv=$9 rip=${10:-}

  # 누적값을 구간별로 쪼갠다. curl 원본은 누적이라 그대로 읽으면 오해한다.
  awk -v d="$dns" -v c="$con" -v t="$tls" -v f="$ttfb" -v o="$tot" -v J="$JSON" '
    function ms(x){ return sprintf("%6.0f", x*1000) }
    J==1 { exit }
    {
      printf "  %s %-13s %s ms\n", "'"$IN"'", "DNS",     ms(d)
      printf "  %s %-13s %s ms\n", "'"$IN"'", "TCP",     ms(c-d)
      if (t>0) printf "  %s %-13s %s ms\n", "'"$IN"'", "TLS", ms(t-c)
      printf "  %s %-13s %s ms   %s\n", "'"$IN"'", "서버 대기", ms(f-(t>0?t:c)), "← 여기만 크면 서버가 느린 것"
      printf "  %s %-13s %s ms\n", "'"$IN"'", "본문 수신", ms(o-f)
      printf "  %s %-13s %s ms\n", "'"$C_B"'━'"$C_RST"'", "합계", ms(o)
    }' <<< x

  local mark="$OK"
  case "$code" in
    2*) mark="$OK";;
    3*) mark="$OK";;
    401|403) mark="$NG"; finding CRIT L6 "HTTP $code — 인증/권한 거부. 망은 정상이고 키·토큰·IP 허용목록 문제다.";;
    400|404|405|410) mark="$WN";;
    429) mark="$NG"; finding CRIT L6 "HTTP 429 — 호출 한도 초과. 차단이 아니라 사용량 문제다.";;
    5*) mark="$NG"; finding CRIT L6 "HTTP $code — 서버 오류. 상대 쪽 문제다.";;
    000) mark="$NG"; finding CRIT L6 "HTTP 응답 없음. 아래 L4/L5 결과를 본다.";;
    *) mark="$WN";;
  esac
  row "$mark" "응답" "HTTP $code  (HTTP/$hv, ${size}B, 리다이렉트 ${nred}회, 서버IP ${rip:-?})"
  # 리다이렉트를 한 줄로 뭉뚱그리면 어디서 엉뚱한 데로 튀는지 못 본다.
  # 헤더 파일에는 각 단계의 응답이 순서대로 다 들어 있다 — 그대로 펼친다.
  if [ "$nred" != 0 ] && [ "$nred" != "" ] && [ "$JSON" != 1 ]; then
    row "$IN" "이동 경로" "$nred 단계"
    awk 'BEGIN{n=0}
      /^HTTP\//{code=$2}
      tolower($1)=="location:"{sub(/\r/,"",$2); n++; printf "        %d) %s → %s\n", n, code, $2}' "$hdr"
  fi

  local srv loc
  srv=$(awk -F': ' 'tolower($1)=="server"{sub(/\r/,"",$2); print $2}' "$hdr" | tail -1)
  loc=$(awk -F': ' 'tolower($1)=="location"{sub(/\r/,"",$2); print $2}' "$hdr" | tail -1)
  [ -n "$srv" ] && row "$IN" "Server" "$srv"
  [ -n "$loc" ] && row "$IN" "최종 이동" "$loc"

  # 중간에 캐시·프록시가 끼어 있으면 내가 보는 것이 원본 서버의 답이 아니다.
  # 그 사실을 모르면 "서버가 이상하다" 로 잘못 몰아간다.
  local mid
  mid=$(awk -F': ' 'BEGIN{IGNORECASE=1}
        tolower($1) ~ /^(via|x-cache|x-cache-hits|cf-ray|x-amz-cf-id|x-served-by|x-varnish|age|x-proxy|x-forwarded-for)$/ {
          sub(/\r/,"",$2); printf "%s=%s ", tolower($1), substr($2,1,26) }' "$hdr")
  [ -n "$mid" ] && {
    row "$IN" "중간 경유" "$(printf '%s' "${mid% }" | cut -c1-72)"
    note "이 응답은 원본 서버가 아니라 캐시·프록시가 준 것일 수 있다"; }

  # HTTP/3 를 광고하는데 우리가 h3 로 못 붙었다면 UDP 443 이 막힌 것일 수 있다.
  local altsvc
  altsvc=$(awk -F': ' 'tolower($1)=="alt-svc"{sub(/\r/,"",$2); print $2}' "$hdr" | tail -1)
  case "$altsvc" in
    *h3*) [ "$hv" = 3 ] || row "$IN" "HTTP/3" "서버는 h3 를 광고하는데 HTTP/$hv 로 붙었다 (UDP 443 차단 가능성)";;
  esac

  # 상태코드가 200 이어도 본문이 거절인 경우가 있다. 차단·한도는 대개 이 모양으로 온다.
  # (BSD grep 의 -o 는 한글이 섞인 줄에서 어긋난다. awk 로 위치를 잡아 잘라 낸다.)
  if [ -s "$body" ]; then
    local peek
    peek=$(head -c 2000 "$body" | tr -d '\000' | tr '\n\r\t' '   ' | sed 's/  */ /g; s/^ //')

    # API 게이트웨이는 오류를 XML/JSON 필드에 담아 보낸다. 그 값이 곧 원인이다.
    local emsg
    emsg=$(printf '%s' "$peek" | sed -n \
      -e 's/.*<errMsg>\([^<]*\)<\/errMsg>.*/\1/p' \
      -e 's/.*"errMsg" *: *"\([^"]*\)".*/\1/p' \
      -e 's/.*<returnAuthMsg>\([^<]*\)<\/returnAuthMsg>.*/\1/p' | head -2 | tr '\n' ' ')
    [ -n "$emsg" ] && row "$NG" "서버 메시지" "${emsg% }"

    local pat hit
    for pat in 'LIMITED_NUMBER_OF_SERVICE_REQUESTS' 'SERVICE_KEY_IS_NOT_REGISTERED' \
               'errMsg' 'rate.?limit' 'quota exceed' 'Access Denied' 'Forbidden' \
               'warning\.or\.kr' 'unauthor' 'captcha' 'Just a moment'; do
      hit=$(printf '%s' "$peek" | awk -v p="$pat" '
        { if (match(tolower($0), tolower(p))) {
            st = RSTART - 30; if (st < 1) st = 1
            print substr($0, st, 130); exit } }')
      [ -n "$hit" ] || continue
      [ -n "$emsg" ] || row "$NG" "본문 경고" "…$hit…"
      finding CRIT L6 "HTTP $code 이고 본문이 거절 응답이다${emsg:+ — $emsg}. 망은 정상이고 애플리케이션 계층에서 막혔다."
      break
    done
  fi
  return 0
}

# ══════════════════════════ L7 · 경로 ══════════════════════════
# 마지막으로 "대답한" 홉을 찾고, 그 홉이 누구 것인지로 책임 구간을 가른다.
# 문제는 마지막 홉이 아니라 그 *다음* 구간에 있다.
trace_raw() { # ip outfile
  local ip=$1 out=$2 mode
  for mode in "" "-I"; do
    runto $((MAXHOP*TRQ+15)) traceroute -n $mode -w 1 -q "$TRQ" -m "$MAXHOP" "$ip" 2>/dev/null > "$out"
    if awk 'NR>1 && $2 ~ /^[0-9a-fA-F]/ {n++} END{exit !(n>1)}' "$out"; then
      printf '%s' "${mode:-UDP}" > "$out.mode"; return 0
    fi
  done
  printf '%s' "무응답" > "$out.mode"; return 1
}

# "홉 IP목록 최소RTT 응답수 손실수" 로 정규화한다.
# 홉당 여러 번 보내면 손실률과 ECMP(경로가 갈라짐)까지 보인다.
trace_hops() { # file
  # 경로가 갈리는(ECMP) 홉은 traceroute 가 여러 줄로 뱉는다. 이어지는 줄은
  # 홉 번호 없이 IP 로 시작하므로, 그것까지 같은 홉으로 묶어야 한다.
  # (묶지 않으면 이어진 줄이 저마다 별개의 홉으로 잘못 읽힌다.)
  awk '
    function proc(st,   i) {
      for (i = st; i <= NF; i++) {
        if ($i == "*") { lost++; continue }
        if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]*:[0-9a-fA-F:]+$/) {
          if (index("," ips ",", "," $i ",") == 0) ips = (ips == "" ? $i : ips "," $i)
          continue
        }
        if ($(i+1) == "ms" && $i ~ /^[0-9.]+$/) {
          recv++
          if (best == "" || $i + 0 < best + 0) best = $i
        }
      }
    }
    function flush() {
      if (cur != "") print cur, (ips == "" ? "*" : ips), (best == "" ? "-" : best), recv, lost
    }
    /^ *[0-9]+ / && $1 ~ /^[0-9]+$/ {
      flush(); cur = $1; recv = 0; lost = 0; ips = ""; best = ""; proc(2); next
    }
    { if (cur != "") proc(1) }
    END { flush() }
  ' "$1"
}

stage_path() { # host port
  local h=$1 ips ip f
  [ "$TRACE" = 1 ] || return 0
  ips=$(kget "ips.$h"); ip=$(first_ip "$ips")
  [ -n "$ip" ] || return 0
  is_sinkhole "$ip" && return 0

  sect "L7 · 경로 — 어디까지 갔고, 거기가 누구 땅인가"
  f="$WORK/tr.$h"
  trace_raw "$ip" "$f"
  local mode; mode=$(cat "$f.mode" 2>/dev/null)
  [ "$mode" = "-I" ] && note "UDP 가 막혀 ICMP 로 전환했다"

  local last="" lastn=0 n hip rtt
  trace_hops "$f" > "$f.hops"
  if [ ! -s "$f.hops" ]; then
    row "$NG" "traceroute" "한 홉도 응답이 없다 — ICMP/UDP 가 전부 막힌 망일 수 있다"
    note "sudo traceroute -n -P TCP -p 443 $ip 로 다시 재 보면 뚫리는 경우가 있다"
    return 1
  fi

  # 홉 소유자·이름을 한꺼번에 미리 조회한다 (순차 조회는 너무 느리다)
  prefetch_meta "$(awk '$2!="*"{print $2}' "$f.hops" | tr '\n' ' ')"

  # 표로 만들어 두고 한 번에 그린다: 홉 IP RTT Δ AS이름 PTR
  local tsv="$f.tsv"; : > "$tsv"
  local prev_rtt="" prev_as="" maxjump=0 jump_at="" jump_from="" jump_to=""
  local anyloss=0
  while read -r n hips rtt recv lost; do
    if [ "$hips" = "*" ]; then
      printf '%s\t*\t-\t-\t-\t-\t-\t-\t0/%s\n' "$n" "$((recv+lost))" >> "$tsv"
      continue
    fi
    local hip ecmp=""
    hip=${hips%%,*}
    case "$hips" in *,*) ecmp=" ECMP";; esac
    [ "$lost" -gt 0 ] 2>/dev/null && anyloss=1
    local asnum asname ptr cls delta edge
    asnum=$(ipmeta "$hip" 1); asname=$(ipmeta "$hip" 7)
    ptr=$(ptr_of "$hip"); cls=$(ip_class "$hip")
    [ "$asnum" = "-" ] && asname="$cls"

    # 앞 홉과의 지연 차이. 어느 구간에서 시간이 뛰는지가 여기서 보인다.
    if [ -n "$prev_rtt" ] && [ "$rtt" != "-" ]; then
      delta=$(awk -v a="$rtt" -v b="$prev_rtt" 'BEGIN{printf "%+.1f", a-b}')
      local d; d=$(awk -v a="$rtt" -v b="$prev_rtt" 'BEGIN{printf "%.1f", a-b}')
      if awk -v x="$d" -v m="$maxjump" 'BEGIN{exit !(x>m)}'; then
        maxjump=$d; jump_at=$n; jump_from=$prev_as; jump_to=$asnum
      fi
    else
      delta="-"
    fi
    [ "$rtt" != "-" ] && prev_rtt=$rtt

    edge="-"
    if [ -n "$prev_as" ] && [ "$asnum" != "$prev_as" ] && [ "$asnum" != "-" ] && [ "$prev_as" != "-" ]; then
      edge="망경계"
    fi
    [ "$asnum" != "-" ] && prev_as=$asnum

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s/%s\n' \
      "$n" "$hip" "$rtt" "$delta" "${asnum:--}" "$(as_short "$asname")$ecmp" "${ptr:--}" "$edge" \
      "$recv" "$((recv+lost))" >> "$tsv"
    last=$hip; lastn=$n
  done < "$f.hops"

  if [ "$JSON" != 1 ]; then
    printf '%s    홉  주소                 RTT    증가  응답  AS        소유자%s\n' "$C_DIM" "$C_RST"
    while IFS="$(printf '\t')" read -r n hip rtt delta asnum asname ptr edge got; do
      if [ "$hip" = "*" ]; then
        printf '  %s %s%-3s %s%s\n' "$IN" "$C_DIM" "$n" \
          "무응답 — 이 라우터가 대답을 안 할 뿐, 못 간 것이 아닐 수 있다" "$C_RST"
        continue
      fi
      printf '  %s %-3s %-16s %7s %6s %5s  %-9s %s %s\n' \
        "$([ "$edge" = "망경계" ] && echo "$WN" || echo "$OK")" \
        "$n" "$hip" "$rtt" \
        "$([ "$delta" = "-" ] && echo "" || echo "$delta")" "$got" \
        "$([ "$asnum" = "-" ] && echo "-" || echo "AS$asnum")" "$(pad "$asname" 26)" \
        "$([ "$edge" = "망경계" ] && printf '%s← 망 경계%s' "$C_WN" "$C_RST")"
      [ "$ptr" != "-" ] && printf '        %s↳ %s%s\n' "$C_DIM" "$ptr" "$C_RST"
    done < "$tsv"
    note "'응답' 은 그 홉이 보낸 프로브 중 대답한 횟수다. 'ECMP' 는 그 홉에서 경로가 갈린다는 뜻이다"
    note "RTT 는 ms(최소값). '증가' 의 음수는 ICMP 응답 우선순위 탓이지 이상이 아니다"
  fi

  # 중간 홉의 손실은 라우터가 ICMP 응답을 뒤로 미룬 것일 뿐인 경우가 대부분이다.
  # **끝 홉까지 손실이 이어질 때만** 진짜 경로 손실이다 — 이걸 구분하지 않으면
  # mtr 을 잘못 읽는 흔한 오진이 그대로 재현된다.
  local endloss
  endloss=$(awk -F'\t' '$2!="*" && $9!="" {last=$9} END{print last}' "$tsv")
  if [ "$anyloss" = 1 ]; then
    case "$endloss" in
      "") :;;
      *) local eg el; eg=${endloss%%/*}; el=${endloss##*/}
         if [ "$eg" = "$el" ]; then
           row "$IN" "중간 손실" "있지만 마지막 홉은 $endloss — ICMP 응답 제한이지 경로 손실이 아니다"
         else
           row "$NG" "경로 손실" "마지막 홉까지 $endloss — 실제로 패킷이 버려지고 있다"
           finding CRIT L7 "목적지까지 패킷 손실이 이어진다($endloss). 회선 품질이나 혼잡 문제다."
         fi;;
    esac
  fi

  # ── AS 단위로 접어서 보여 준다. 홉 번호보다 이게 진짜 구간이다. ──
  local aspath
  aspath=$(awk -F'\t' '$2!="*" && $5!="-" {
      if ($5 != cur) { if (cur!="") printf "AS%s %s (%s~%s홉) → ", cur, nm, s0, s1
                       nm=$6; sub(/ ECMP$/,"",nm); cur=$5; nm=substr(nm,1,22); s0=$1 }
      s1=$1
    } END { if (cur!="") printf "AS%s %s (%s~%s홉)", cur, nm, s0, s1 }' "$tsv")
  [ -n "$aspath" ] && { say ""; row "$IN" "AS 경로" "[나] → ${aspath}"; }

  # ── 어느 구간에서 시간이 뛰었는가 ──
  if awk -v m="$maxjump" 'BEGIN{exit !(m>10)}' 2>/dev/null; then
    local jnote=""
    # 사설 홉은 AS 를 모른다. "AS- 로 넘어간다" 같은 헛소리를 붙이지 않는다.
    case "$jump_from$jump_to" in
      *-*) :;;
      *) [ "$jump_from" != "$jump_to" ] && jnote="  (AS$jump_from → AS$jump_to 넘어가는 지점)";;
    esac
    row "$IN" "최대 지연 증가" "${jump_at}홉에서 +${maxjump}ms$jnote"
    note "중간 홉의 지연 자체는 신뢰하지 마라. 의미가 있는 것은 최종 목적지 시간이다"
  fi

  local dest_asn; dest_asn=$(asn_of "$ip")
  kset "path.$h.last" "$last"
  kset "path.$h.lastn" "$lastn"
  kset "path.$h.aspath" "$aspath"

  # 돌아오는 길은 가는 길과 다를 수 있고, 끊긴 쪽이 그쪽일 수도 있다.
  # 응답 패킷의 TTL 로 역방향 홉 수를 역산해 정방향과 비교한다.
  local pttl rhops fhops
  if [ "$(uname)" = Darwin ]; then
    pttl=$(ping -c 2 -W 1000 -t 4 "$ip" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')
  else
    pttl=$(ping -c 2 -W 1 -w 4 "$ip" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')
  fi
  if [ -n "$pttl" ]; then
    # 출발 TTL 은 보통 64·128·255 중 하나다. 받은 값보다 큰 것 중 가장 작은 값을 쓴다.
    local init=255
    [ "$pttl" -le 128 ] 2>/dev/null && init=128
    [ "$pttl" -le 64 ]  2>/dev/null && init=64
    rhops=$((init - pttl))
    fhops=$lastn
    if [ "$rhops" -gt 0 ] 2>/dev/null && [ "$fhops" -gt 0 ] 2>/dev/null; then
      local diff=$((fhops - rhops)); [ "$diff" -lt 0 ] && diff=$((-diff))
      if [ "$diff" -ge 3 ]; then
        row "$WN" "역경로" "돌아오는 길은 ${rhops}홉, 가는 길은 ${fhops}홉 — 경로가 비대칭이다"
        note "장애가 돌아오는 길에 있으면 traceroute 로는 안 보인다. 상대 쪽에서 반대로 재 봐야 한다"
        finding INFO L7 "왕복 경로가 비대칭이다(가는 길 ${fhops}홉, 오는 길 ${rhops}홉). 역방향 장애는 이쪽에서 관측할 수 없다."
      else
        row "$IN" "역경로" "돌아오는 길 약 ${rhops}홉 (가는 길 ${fhops}홉과 비슷)"
      fi
    fi
  fi

  if [ "$last" = "$ip" ]; then
    row "$OK" "도달" "목적지까지 경로가 살아 있다 ($lastn 홉)"
  elif [ "$(kget "tcpok.$h")" = 1 ]; then
    # TCP 가 붙었다는 것은 패킷이 목적지까지 갔다 왔다는 뜻이다.
    # traceroute 가 안 보이는 것은 목적지·중간 장비가 ICMP/UDP 를 막기 때문이다.
    say ""
    row "$OK" "도달" "traceroute 는 ${lastn}홉까지만 보이지만 TCP 는 도달했다"
    note "목적지나 중간 장비가 ICMP·UDP 만 막는 것이다. 경로 문제가 아니다"
    finding INFO L7 "traceroute 가 ${lastn}홉에서 멈추지만 TCP 는 성공한다 — ICMP/UDP 필터링일 뿐 경로는 정상이다."
  else
    say ""
    row "$NG" "끊긴 지점" "마지막 응답 = ${lastn}홉 $last  [$(asn_of "$last")]"
    [ -n "$(ptr_of "$last")" ] && note "그 홉의 이름: $(ptr_of "$last")"
    row "$IN" "목적지" "$ip  [$dest_asn]"
    local la da; la=$(asn_of "$last"); la=${la%% *}; da=${dest_asn%% *}
    if is_private "$last"; then
      finding CRIT L7 "${lastn}홉($last)이 사설 대역이다 — 아직 ISP 내부에서 끊겼다. 통신사 소관이다."
    elif [ "$la" = "$da" ] && [ "$la" != "-" ]; then
      finding CRIT L7 "마지막 응답 홉과 목적지가 같은 AS($la)다 — 상대 망 안에서 끊겼다. 상대 쪽 소관이다."
    else
      finding CRIT L7 "$last($(asn_of "$last")) 다음에서 끊긴다. 이 홉과 목적지 AS($da) 사이 구간이 원인이다."
    fi
    note "문제는 $last 가 아니라 그 *다음* 구간이다. $last 는 마지막으로 대답한 곳일 뿐이다."
  fi
}

# 정상인 목적지와 경로를 겹쳐 보고, 어디서 갈라지는지 찾는다.
# 같은 홉까지 똑같이 가다가 한쪽만 죽으면 그 갈림 이후가 범인이다.
stage_path_diff() { # host
  local h=$1 ok_ip fb fa
  [ "$TRACE" = 1 ] || return 0
  ok_ip=$(kget baseline_ok_ip)
  [ -n "$ok_ip" ] || return 0
  fa="$WORK/tr.$h.hops"; [ -s "$fa" ] || return 0

  fb="$WORK/tr.base"
  trace_raw "$ok_ip" "$fb" || return 0
  trace_hops "$fb" > "$fb.hops"
  [ -s "$fb.hops" ] || return 0

  sect "L7b · 정상 경로와 대조 — 어디서 갈라지는가"
  # 홉의 IP 는 ECMP 면 여러 개다. 통째로 비교하면 순서만 달라도 어긋난다 —
  # 하나라도 겹치면 같은 지점을 지난 것으로 본다.
  # 무응답(*) 홉은 "다르다" 가 아니라 "모른다" 이므로 끊지 않고 넘어간다.
  local same=0 n a b x hit
  n=1
  while [ "$n" -le "$MAXHOP" ]; do
    a=$(awk -v k="$n" '$1==k{print $2; exit}' "$fa")
    b=$(awk -v k="$n" '$1==k{print $2; exit}' "$fb.hops")
    [ -n "$a" ] && [ -n "$b" ] || break
    if [ "$a" = "*" ] || [ "$b" = "*" ]; then n=$((n+1)); continue; fi
    hit=0
    for x in $(printf '%s' "$a" | tr ',' ' '); do
      case ",$b," in *",$x,"*) hit=1;; esac
    done
    [ $hit = 1 ] || break
    same=$n; n=$((n+1))
  done
  if [ "$same" -gt 0 ]; then
    local shared; shared=$(awk -v k="$same" '$1==k{print $2}' "$fa")
    row "$OK" "공통 구간" "1~${same}홉이 정상 경로와 동일 ($shared 까지)"
    note "여기까지는 내 기기·공유기·ISP 진입이 정상이라는 뜻이다 — 그 구간은 용의선상에서 빠진다"
    finding INFO L7 "정상 목적지와 ${same}홉까지 경로가 같다. 공유기·ISP 진입 구간은 무죄다."
  else
    row "$WN" "공통 구간" "첫 홉부터 다르다 — 경로가 아예 갈린다"
  fi
}

# ══════════════════════ L8 · PMTU (--full) ══════════════════════
# "붙기는 붙는데 큰 응답에서 멈춘다" 의 전형적 원인. TLS 핸드셰이크 중간에 멈추면 이걸 의심한다.
stage_pmtu() { # host
  local h=$1 ip s okmax=0
  [ "$MODE" = full ] || return 0
  ip=$(first_ip "$(kget "ips.$h")"); [ -n "$ip" ] || return 0
  is_sinkhole "$ip" && return 0
  sect "L8 · PMTU — 큰 패킷이 조용히 버려지는가"
  for s in 1472 1452 1420 1400 1300 1200; do
    if [ "$(uname)" = Darwin ]; then
      ping -c 1 -W 1500 -D -s "$s" "$ip" >/dev/null 2>&1
    else
      ping -c 1 -W 2 -M do -s "$s" "$ip" >/dev/null 2>&1
    fi
    if [ $? -eq 0 ]; then okmax=$s; row "$OK" "${s}B" "통과 (MTU $((s+28)))"; break
    else row "$NG" "${s}B" "막힘"; fi
  done
  if [ "$okmax" = 0 ]; then
    row "$IN" "판정" "전 구간 무응답 — ICMP 를 막는 경로다. PMTU 판정 불가"
  elif [ "$okmax" -lt 1472 ]; then
    row "$WN" "판정" "유효 MTU $((okmax+28)) — 1500 보다 작다"
    finding WARN L8 "경로 MTU 가 $((okmax+28)) 로 줄어 있다. 큰 응답만 멈추는 증상의 원인일 수 있다."
  fi
}

# ══════════════════════ L9 · 대조군 ══════════════════════
# 한 곳만 재면 아무것도 모른다. 정상이어야 하는 곳과 나란히 재야 회선 문제가 갈린다.
stage_baseline() {
  sect "L9 · 대조군 — 회선 자체는 멀쩡한가"
  local t bh bp ip r up=0 tot=0
  for t in $BASELINE; do
    bh=${t%:*}; bp=${t##*:}; [ "$bh" = "$bp" ] && bp=$DEF_PORT
    if is_ip_literal "$bh"; then ip=$bh; else ip=$(dig_ips "$bh" A | head -1); fi
    if [ -z "$ip" ]; then
      # 이름을 못 푼 것은 회선이 죽은 것과 다르다. 실패로 세지 않는다.
      row "$WN" "$bh:$bp" "이름 해석 실패 — 대조군에서 제외한다"
      continue
    fi
    tot=$((tot+1))
    r=$(tcp_probe_n "$ip" "$bp" 1)
    case "$r" in
      *OPEN*) up=$((up+1)); row "$OK" "$bh:$bp" "$ip  $(echo "$r" | awk '{print $3}')ms"
              [ -n "$(kget baseline_ok_ip)" ] || kset baseline_ok_ip "$ip";;
      *) row "$NG" "$bh:$bp" "$ip  $(echo "$r" | awk '{print $5}')";;
    esac
  done
  kset base_up "$up"; kset base_tot "$tot"
  if [ $tot -eq 0 ]; then
    row "$WN" "판정" "쓸 수 있는 대조군이 없다 — 비교 없이 판단해야 한다"
    finding WARN L9 "대조군을 하나도 못 세웠다. --baseline 값을 확인한다."
  elif [ $up -eq 0 ]; then
    # L2 는 IP 로만 붙어 보는 검사다. 그게 성공했는데 대조군이 전부 실패하면
    # 회선이 아니라 대조군 쪽 문제다 — 여기서 갈라야 자기모순이 안 생긴다.
    if [ "$(kget inet_up 0)" -gt 0 ] 2>/dev/null; then
      row "$WN" "판정" "대조군은 전부 실패했지만 L2 는 정상이다 — 회선 문제가 아니다"
      finding WARN L9 "대조군에 못 붙었으나 IP 직접 접속(L2)은 된다. 대조군 설정이나 이름 해석 문제다."
    else
      finding CRIT L9 "대조군까지 전부 막힌다. 목적지가 아니라 내 회선·기기 문제다."
    fi
  elif [ $up -eq $tot ]; then
    finding INFO L9 "대조군 $up/$tot 정상. 회선 자체는 멀쩡하므로 목적지 방향만의 문제다."
  fi
}

# ══════════════════════════ 판정 ══════════════════════════
# 관측을 결론으로 바꾼다. 결론에는 반드시 "누구 소관이고 무엇을 말해야 하는가"가 붙는다.
verdict() {
  sect "판정 — 어디서 막혔고 누구 소관인가"
  if [ ! -s "$FIND" ]; then
    row "$OK" "결론" "모든 계층 통과. 이 경로에는 문제가 없다."
    return 0
  fi
  local lv layer msg seen="$WORK/seen"; : > "$seen"
  for lv in CRIT WARN INFO; do
    while IFS="$(printf '\t')" read -r l layer msg; do
      [ "$l" = "$lv" ] || continue
      grep -qxF "$msg" "$seen" && continue
      printf '%s\n' "$msg" >> "$seen"
      case "$lv" in
        CRIT) printf '  %s %-4s %s\n' "$NG" "$layer" "$msg";;
        WARN) printf '  %s %-4s %s\n' "$WN" "$layer" "$msg";;
        *)    printf '  %s %-4s %s\n' "$IN" "$layer" "$msg";;
      esac
    done < "$FIND"
  done

  # 책임 구간 — 가장 얕은 CRIT 계층이 뿌리다. 그 위를 고치기 전엔 아래는 의미가 없다.
  local deep
  deep=$(awk -F'\t' '$1=="CRIT"{print $2}' "$FIND" | sort | head -1)
  say ""
  case "$deep" in
    L0|L1) row "$C_B→$C_RST" "소관" "내 기기 / 우리 집. 공유기·케이블·와이파이부터 고친다.";;
    L2|L9) row "$C_B→$C_RST" "소관" "우리 회선 전체. 통신사에 '인터넷 자체가 안 나간다'로 접수한다.";;
    L2b)   row "$C_B→$C_RST" "소관" "안 되는 쪽 회선의 통신사. 다른 회선으로는 같은 목적지가 열린다.";;
    L3)    row "$C_B→$C_RST" "소관" "이름 해석. 공유기 DNS·보안SW·회사 정책을 본다. DNS 를 바꿔도 안 되면 투명 가로채기다.";;
    L3b)   row "$C_B→$C_RST" "소관" "이름·도메인 자체. 오타·미등록·만료·권위 서버 장애다 — 망을 아무리 봐도 안 나온다."
           note "철자부터 확인하고, whois 로 등록 상태를 본다.";;
    L4|L7)
      # 대상이 여럿이면 "첫 번째" 가 아니라 **실제로 막힌** 대상을 인용해야 한다.
      local h last lastn cand
      h=""
      for cand in $TARGETS; do
        cand=${cand%%:*}; cand=${cand#[}; cand=${cand%]}
        if [ "$(kget "tcpok.$cand" 1)" = 0 ]; then h=$cand; break; fi
      done
      [ -n "$h" ] || { h=$(printf '%s' "$TARGETS" | awk '{print $1}'); h=${h%%:*}; }
      last=$(kget "path.$h.last"); lastn=$(kget "path.$h.lastn")
      if grep -qE '광고되지 않는|쓰이지 않는 주소|목적지가 될 수 없다|포트 지정이 잘못|대상 지정이 잘못' "$FIND"; then
        row "$C_B→$C_RST" "소관" "입력한 대상 자체. 망 문제가 아니라 주소·포트가 잘못됐다."
        note "DNS 가 준 답이나 설정 파일에 적힌 주소·포트가 맞는지부터 본다."
      elif grep -q '호스트는 살아 있고' "$FIND"; then
        # 다른 포트는 대답한다 → 패킷은 목적지까지 갔다. 경로 문제가 아니다.
        row "$C_B→$C_RST" "소관" "상대 서버의 포트 정책. 경로는 살아 있다 — 그 포트만 골라 막혔다."
        note "상대에게 이렇게 말한다: \"해당 포트가 우리 IP 에서 열리지 않는다. 허용목록을 확인해 달라\""
      elif grep -q 'RST 로 거절' "$FIND"; then
        row "$C_B→$C_RST" "소관" "상대 서버. 패킷은 도착했고 서버가 거절했다 — 서비스가 안 떠 있다."
      else
        row "$C_B→$C_RST" "소관" "경로 구간. 상대 서버도, 내 기기도 아니다."
        [ -n "$last" ] && note "통신사에 이렇게 말한다: \"${lastn}홉 $last 이후 $(first_ip "$(kget "ips.$h")") 방향으로 도달하지 못한다\""
      fi
      ;;
    L5)    row "$C_B→$C_RST" "소관" "TLS. 인증서(상대) 또는 가로채기 장비(중간). curl -v 로 더 본다.";;
    L6)    row "$C_B→$C_RST" "소관" "애플리케이션. 망은 정상이다 — 키·권한·한도·서버 오류를 본다.";;
    L8)    row "$C_B→$C_RST" "소관" "경로 MTU. 공유기 MTU 를 1400 으로 낮춰 재현되는지 본다.";;
    *)     row "$C_B→$C_RST" "소관" "치명적 실패 없음. 위 경고만 확인하면 된다.";;
  esac

  # 여기서 더 좁힐 수 없는 지점을 명시한다. 추측으로 넘어가지 않는다.
  case "$deep" in
    L4|L7)
      if ! grep -qE '호스트는 살아 있고|RST 로 거절|광고되지 않는|쓰이지 않는 주소|지정이 잘못' "$FIND"; then
        note "여기서 더 좁힐 수단은 없다. 같은 시각에 다른 회선(휴대폰 테더링)으로 재보면"
        note "열리면 우리 통신사 경로 문제, 안 열리면 상대 망 장애로 갈린다."
      fi;;
  esac
  awk -F'\t' '$1=="CRIT"{n++} END{exit n?1:0}' "$FIND"
}

# ══════════════════════════ JSON ══════════════════════════
# whois 값에는 따옴표·역슬래시가 들어올 수 있다. 그대로 넣으면 JSON 이 깨진다.
jesc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037'; }

emit_json() {
  local h ips
  printf '{\n  "version":"%s","time":"%s","mode":"%s",\n' "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MODE"
  printf '  "local":{"gateway":"%s","interface":"%s","address":"%s","public":"%s","mtu":"%s","resolvers":"%s"},\n' \
    "$(kget gw)" "$(kget iface)" "$(kget myip)" "$(kget pubip)" "$(kget mtu)" "$(jesc "$(dns_servers)")"
  printf '  "internet":{"reachable":%s,"tried":%s},\n' "$(kget inet_up 0)" "$(kget inet_tot 0)"
  printf '  "baseline":{"up":%s,"total":%s},\n' "$(kget base_up 0)" "$(kget base_tot 0)"
  printf '  "targets":['
  local first=1
  for t in $TARGETS; do
    h=${t%%:*}
    [ $first = 1 ] || printf ','
    first=0
    ips=$(kget "ips.$h" | tr '\n' ' ')
    local fip; fip=$(first_ip "$ips")
    printf '\n    {"host":"%s","ips":"%s","truth":"%s",' "$(jesc "$h")" "${ips% }" "$(kget "truth.$h")"
    printf '"asn":"%s","as_name":"%s","bgp_prefix":"%s","country":"%s","registry":"%s","allocated":"%s",' \
      "$(jesc "$(ipmeta "$fip" 1)")" "$(jesc "$(ipmeta "$fip" 7)")" "$(jesc "$(ipmeta "$fip" 3)")" \
      "$(jesc "$(ipmeta "$fip" 4)")" "$(jesc "$(ipmeta "$fip" 5)")" "$(jesc "$(ipmeta "$fip" 6)")"
    printf '"ptr":"%s","kind":"%s","netname":"%s","abuse":"%s","tcp_ok":%s,' \
      "$(jesc "$(ptr_of "$fip")")" "$(jesc "$(ip_kind "$fip")")" \
      "$(jesc "$(rirfield "$fip" 'netname|NetName')")" \
      "$(jesc "$(rirfield "$fip" 'abuse-mailbox|OrgAbuseEmail|e-mail')")" \
      "$([ "$(kget "tcpok.$h" 0)" = 1 ] && echo true || echo false)"
    printf '"as_path":"%s","last_hop":"%s","last_hop_owner":"%s"}' \
      "$(jesc "$(kget "path.$h.aspath")")" "$(kget "path.$h.last")" \
      "$(jesc "$([ -n "$(kget "path.$h.last")" ] && asn_of "$(kget "path.$h.last")")")"
  done
  printf '\n  ],\n  "findings":['
  first=1
  while IFS="$(printf '\t')" read -r l layer msg; do
    [ $first = 1 ] || printf ','
    first=0
    printf '\n    {"level":"%s","layer":"%s","message":"%s"}' "$l" "$layer" "$(printf '%s' "$msg" | sed 's/"/\\"/g')"
  done < "$FIND"
  printf '\n  ]\n}\n'
}

# ══════════════════════════ 본체 ══════════════════════════
[ "$JSON" = 1 ] || {
  printf '%s%s v%s%s  %s  %s모드\n' "$C_B" "netcheck" "$VERSION" "$C_RST" \
    "$(date '+%Y-%m-%d %H:%M:%S')" "$MODE"
  printf '%s대상: %s   대조군: %s%s\n' "$C_DIM" "${TARGETS# }" "$BASELINE" "$C_RST"
  [ -n "$PY" ] || printf '%s경고: python3 가 없어 TCP 실패 원인(드롭/RST/도달불가)을 구분할 수 없다%s\n' "$C_WN" "$C_RST"
}

stage_local
stage_link
stage_internet
stage_baseline

for t in $TARGETS; do
  case "$t" in
    \[*\]:*) h=${t%]:*}; h=${h#[}; p=${t##*]:};;
    *:*)     h=${t%:*}; p=${t##*:};;
    *)       h=$t; p=$DEF_PORT;;
  esac
  if [ -z "$h" ]; then
    row "$NG" "대상" "호스트가 비어 있다: '$t'"
    finding CRIT L4 "대상 지정이 잘못됐다: '$t'"
    continue
  fi
  if ! valid_port "$p"; then
    [ "$JSON" = 1 ] || printf '\n%s%s══ %s:%s%s\n' "$C_B" "$C_IN" "$h" "$p" "$C_RST"
    row "$NG" "포트" "$p 는 포트 번호가 아니다 (1~65535)"
    finding CRIT L4 "$h 의 포트 지정이 잘못됐다: $p"
    continue
  fi
  [ "$JSON" = 1 ] || printf '\n%s%s══ %s:%s %s%s\n' "$C_B" "$C_IN" "$h" "$p" \
    "$(pad=$(( 46 - ${#h} - ${#p} )); [ $pad -lt 2 ] && pad=2; printf '%*s' $pad '' | tr ' ' '=')" "$C_RST"

  if stage_dns "$h"; then
    stage_domain "$h"
    stage_multipath "$h" "$p"
    if stage_tcp "$h" "$p"; then
      [ "$MODE" = quick ] || stage_identity "$h" "$p"
      stage_tls  "$h" "$p"
      stage_http "$h" "$p"
      # 붙더라도 경로는 본다 — 느려지거나 간헐적일 때 원인이 거기 있다.
      # 빠르게만 보고 싶으면 -q / --no-trace 를 쓴다.
      stage_path "$h"; stage_path_diff "$h"
      [ "$MODE" = full ] && stage_pmtu "$h"
    else
      # 붙지 않을수록 상대가 무엇인지가 더 중요해진다.
      [ "$MODE" = quick ] || stage_identity "$h" "$p"
      stage_path "$h"
      stage_path_diff "$h"
      stage_pmtu "$h"
    fi
  fi
done

if [ "$JSON" = 1 ]; then
  emit_json
  awk -F'\t' '$1=="CRIT"{n++} END{exit n?1:0}' "$FIND"
else
  verdict
fi
