# 사용 설명서

`netcheck` 의 설치·실행·출력 해석·GUI·데스크톱 앱·빌드 방법. 진단 원리는 [diagnosis.md](diagnosis.md).

## 목차

1. [요구 사항](#1-요구-사항)
2. [빠른 시작](#2-빠른-시작)
3. [명령줄 (CLI)](#3-명령줄-cli)
4. [출력 읽기](#4-출력-읽기)
5. [JSON · 보고서](#5-json--보고서)
6. [반복 관측](#6-반복-관측)
7. [프록시](#7-프록시)
8. [GUI](#8-gui)
9. [데스크톱 앱](#9-데스크톱-앱)
10. [빌드 · 배포](#10-빌드--배포)
11. [Windows 참고](#11-windows-참고)
12. [판정 시험](#12-판정-시험)
13. [문제 해결](#13-문제-해결)

---

## 1. 요구 사항

| 구분 | 필요 항목 |
|---|---|
| CLI · 브라우저 GUI | Python 3.8 이상 (표준 라이브러리만 사용), `traceroute`/`tracert`, `ping` |
| 데스크톱 앱 실행·빌드 | `pip install -r tools/requirements-app.txt` (pywebview, PyInstaller) |
| Linux 데스크톱 앱 | WebKitGTK (`sudo apt install gir1.2-webkit2-4.1 python3-gi`) |
| Windows 데스크톱 앱 | WebView2 런타임 (Windows 10/11 기본 포함) |

- 관리자 권한 불필요 (TCP 홉 거리 측정 포함)
- 외부 조회: DoH(1.1.1.1·8.8.8.8), Team Cymru whois, RIPE stat, RIR whois, crt.sh(`--ct`·`-f` 일 때만)

---

## 2. 빠른 시작

```bash
git clone https://github.com/zz1231me/netcheck.git
cd netcheck
```

```bash
python3 tools/netcheck.py www.example.com            # CLI
python3 tools/netcheck-gui.py                        # 브라우저 GUI
python3 tools/netcheck-app.py                        # 데스크톱 창 (pywebview 필요)
```

```mermaid
flowchart LR
  A["대상 입력<br/>호스트 · URL"] --> B["netcheck 실행<br/>CLI · GUI · 앱"]
  B --> C["계층별 검사<br/>L0 → L9"]
  C --> D["판정<br/>근본 원인 계층 · 원인 구간"]
  D --> E["조치·문의<br/>보고서 · JSON"]
```

---

## 3. 명령줄 (CLI)

### 대상 형식

| 입력 | 해석 |
|---|---|
| `example.com` | 기본 포트(443) |
| `example.com:8080` | 포트 지정 |
| `https://example.com/api/v1?x=1` | 스킴·포트·경로·질의 그대로 사용 (사용자 정보 `user@` 는 제외) |
| `example.com/path` | 경로 지정 (스킴 없음) |
| `[2001:db8::1]:443`, `2001:db8::1` | IPv6 주소 |
| `a.com b.com c.com:22` | 여러 대상 — 대상별로 따로 판정 |

### 자주 쓰는 명령

```bash
python3 tools/netcheck.py -b api.example.com                 # 결론과 조치만
python3 tools/netcheck.py api.example.com www.example.org    # 여러 대상 비교 (의심 + 정상)
python3 tools/netcheck.py -q api.example.com                 # 빠른 검사 (경로·도메인·목적지 정보 생략)
python3 tools/netcheck.py -f api.example.com                 # 전체 검사 (포트 스캔·PMTU·CT)
python3 tools/netcheck.py -r 10 -i 5 api.example.com         # TCP 10회, 5초 간격 (간헐 장애)
python3 tools/netcheck.py --json api.example.com > r.json    # JSON
python3 tools/netcheck.py --report r.md api.example.com      # Markdown 보고서
```

### 검사 범위

| 범위 | 옵션 | 포함 | 생략 |
|---|---|---|---|
| 빠른 검사 | `-q` | L0·L1·L2·L9, L3, L4, L5, L6 | L3b·L4b·L6b·L7·L7b |
| 기본 | (없음) | 빠른 검사 + 도메인·목적지 정보·URL 변형·경로 | 포트 스캔·PMTU·CT |
| 전체 | `-f` | 기본 + 포트 스캔·PMTU·CT·홉당 프로브 3회 | — |

### 옵션

| 옵션 | 의미 | 기본값 |
|---|---|---|
| `-p N` | 기본 포트 | 443 |
| `-t N` | 연결·응답 타임아웃(초) | 4 |
| `-r N` | TCP 반복 횟수 | 3 |
| `-i N` | 반복 간격(초) | 0 |
| `-m N` | traceroute 최대 홉 | 20 |
| `-4` / `-6` | IPv4 / IPv6 강제 | 둘 다 확인 |
| `-q` / `-f` | 빠른 검사 / 전체 검사 | 기본 |
| `--no-trace` | traceroute 만 생략 | |
| `--ct` / `--no-ct` | CT 로그(crt.sh) 대조 켜기 / `-f` 에서도 끄기 | `-f` 일 때 켜짐 |
| `--no-variants` | URL 변형(https·http·www 조합) 생략 | |
| `--baseline "a:443,b:443"` | 대조군 지정 | `1.1.1.1:443,8.8.8.8:443,www.google.com:443` |
| `--proxy URL` | 프록시 경유 (§7) | |
| `--proxy-system` | 시스템·환경변수 프록시 사용 | |
| `--watch 초` / `--count N` | 반복 관측 (§6) | |
| `--report 파일` | Markdown 보고서 저장 | |
| `-b` | 결론과 조치만 출력 | |
| `--json` | JSON 출력 | |
| `--no-color` | 색 끔 | 터미널이면 색 사용 |

### 종료 코드

| 값 | 의미 |
|---|---|
| `0` | 치명적 실패 없음 |
| `1` | 치명적 실패 있음 |
| `2` | 사용법 오류 (옵션·대상 지정) |
| `3` | 진단 불완전 — 일부 계층이 예외로 중단 |

스크립트·모니터링 연동 예:

```bash
python3 tools/netcheck.py -q -b api.example.com || echo "접속 이상 (종료 코드 $?)"
```

---

## 4. 출력 읽기

기본 출력은 계층 순서대로 표시하고 마지막에 **판정**과 **요약**을 출력한다.

```
L4 · TCP 81 — 3-way handshake  (1회)
  ✘ 1.1.1.1          0/1  무응답 — 패킷 드롭  AS13335 Cloudflare, Inc.
  ⚠   ↳ :443         열림 — 호스트 동작 중, 대상 포트만 차단
  ⚠   ↳ :80          열림 — 호스트 동작 중, 대상 포트만 차단
  · IPv6             AAAA 레코드 없음 — IPv4 전용 목적지
```

| 표시 | 의미 |
|---|---|
| `✔` | 정상 |
| `✘` | 실패 (판정에 반영) |
| `⚠` | 경고 |
| `·` | 정보 |
| `→ 원인 구간` | 근본 원인 구간과 조치·문의 내용 |

`-b` 는 상세 없이 발견 사항·원인 구간·조치·요약만 출력한다.

```
1.1.1.1
  ✘ [L4] 1.1.1.1:81 무응답(패킷 드롭). 방화벽 DROP·널 라우팅·경로 단절.

  → 원인 구간  목적지 서버의 포트 정책. 경로는 정상, 해당 포트만 차단.
      목적지 관리자에게: "해당 포트가 우리 공인 IP 에서 연결되지 않음. 허용목록 확인 요청"

요약
  ✘ 1.1.1.1                   L4 · 목적지 포트 정책 — 1.1.1.1:81 무응답(패킷 드롭). …
  ✔ www.weather.go.kr         문제 없음 — 전 계층 통과
```

- 판정 기준: **가장 얕은 계층의 치명적 실패(CRIT)** 를 근본 원인으로 판정 ([diagnosis.md §3](diagnosis.md#3-계층별-검사와-판정))
- 여러 대상: 대상별로 따로 판정. 공통 검사(L0·L1·L2·L9) 실패만 모든 대상에 적용
- 같은 호스트를 다른 포트로 여러 번 지정하면 `host:port` 단위로 분리

### URL 변형 (L6b)

호스트 이름이면 `https://`·`http://` × `www.` 유무 조합을 자동으로 요청해 비교한다.

```
L6b · URL 변형 — https·http·www 조합 응답
  ✔ https://data.go.kr  (입력) 301 → 200  289ms  → https://www.data.go.kr/
  ✔ https://www.data.go.kr 200  211ms
  ⚠ http://data.go.kr 301 → 301  63ms  → http://www.data.go.kr/  (이동 실패: 같은 주소로 반복 이동 — 서버 리다이렉트 설정 오류)
  ⚠ http://www.data.go.kr 301  42ms  (이동 실패: 같은 주소로 반복 이동 — 서버 리다이렉트 설정 오류)
```

- 입력한 주소가 실패하고 다른 조합이 응답하면 경고 (예: www 없는 주소만 실패, HTTPS 만 실패)
- 이름 해석이 실패해도 실행 (도메인 자체는 주소가 없고 `www.` 만 있는 경우 확인)

---

## 5. JSON · 보고서

### JSON (`--json`)

```json
{
  "version": "3.0",
  "mode": "normal",
  "local": {"gateway": "192.168.0.1", "address": "192.168.0.10", "public_ip": "203.0.113.20", "mtu": 1500},
  "internet": {"up": 4, "tried": 4},
  "baseline": {"up": 3, "total": 3},
  "targets": [{
    "key": "1.1.1.1", "host": "1.1.1.1", "port": 81,
    "root_layer": "L4", "who": "목적지 포트 정책",
    "summary": "L4 · 목적지 포트 정책 — 1.1.1.1:81 무응답(패킷 드롭). …",
    "cause": "목적지 서버의 포트 정책. 경로는 정상, 해당 포트만 차단.",
    "actions": ["목적지 관리자에게: \"해당 포트가 우리 공인 IP 에서 연결되지 않음. 허용목록 확인 요청\""],
    "tcp_ok": false, "asn": "13335", "rpki": "valid", "variants": null
  }],
  "invalid_targets": [],
  "findings": [{"level": "CRIT", "layer": "L4", "target": "1.1.1.1", "code": "tcp_fail", "message": "…"}],
  "internal_errors": 0
}
```

| 필드 | 내용 |
|---|---|
| `targets[].root_layer` | 근본 원인 계층 (`null` 이면 치명적 실패 없음) |
| `targets[].who` · `cause` · `actions` | 원인 구간 이름·설명·조치 |
| `targets[].variants` | URL 변형 결과 목록 |
| `findings[].code` | 판정 분류 코드 (`tcp_rst`, `host_alive`, `no_local_v6`, `http_timeout` 등) |
| `invalid_targets` | 입력 오류로 검사하지 못한 대상 |

### 보고서 (`--report 파일`)

통신사·목적지 담당자에게 전달하는 Markdown 문서.

- 측정 시각·위치·**공인 IP**·DNS 서버·프록시·설정
- 대상별 결론·발견 사항, 측정 근거 표 (해석 주소·DoH 응답·TCP·IPv6·MSS·홉 거리·소유자·RPKI·AS 경로·**마지막 응답 홉**)
- URL 변형 표, 홉별 경로 표, 반복 관측 요약(`--watch` 시), 결과 활용 안내, 전체 출력(색 코드 제거)

> 보고서와 JSON 에는 이 기기의 공인 IP·사설 주소가 포함됨. 공개 장소에 올릴 때 확인

---

## 6. 반복 관측

```bash
python3 tools/netcheck.py --watch 60 --count 30 api.example.com     # 1분 간격 30회
python3 tools/netcheck.py --watch 60 --report watch.md api.example.com
```

- 1회차는 전체 출력, 이후 결론이 같으면 한 줄, **결론이 바뀐 회차만 전체 출력**
- 종료(`--count` 도달 또는 Ctrl+C) 시 상시 실패 / 간헐 실패 구분 요약

```
반복 관측 결과 — 30회
  · 기간                 14:00:11 ~ 14:29:11  (29분 0초, 30회)
  ⚠ api.example          4/30회 실패 — 간헐 실패 (L4), 처음 14:05:11 마지막 14:23:11
      일부 회차만 실패 — 부하·경로 변동·일부 노드 불량 확인
```

---

## 7. 프록시

```bash
python3 tools/netcheck.py --proxy http://proxy.corp:3128 api.example.com
python3 tools/netcheck.py --proxy socks5h://127.0.0.1:1080 api.example.com
python3 tools/netcheck.py --proxy-system api.example.com
```

| 방식 | 이름 해석 | 비고 |
|---|---|---|
| `http://` | 프록시 | CONNECT 터널. 평문 HTTP 는 GET 요청 |
| `socks5h://` | 프록시 | 로컬 DNS 차단과 무관 |
| `socks5://` · `socks4://` | 로컬 | |
| 자격증명 | `http://user:pass@host:port` | |

- L0 에서 프록시 자체 연결 확인, L2c 에서 직접 연결과 프록시 연결 비교
- traceroute·ping 은 프록시를 경유하지 않음 (L7 은 직접 경로)

---

## 8. GUI

```bash
python3 tools/netcheck-gui.py               # 브라우저 자동 실행 (기본 포트 8787)
python3 tools/netcheck-gui.py --port 8899 --no-open
```

Windows 11 설정 앱·PowerToys 와 같은 Fluent 레이아웃 (왼쪽 탐색 + 오른쪽 페이지).

| 영역 | 내용 |
|---|---|
| 왼쪽 탐색 | 진단 / 결과(검사 환경 · 대상별 · 원본 출력 · JSON). 항목 옆 점으로 상태, 하단에 진행 상태 |
| 실행 카드 | 대상 · 검사 범위 · 실행/중지, 예시 대상 |
| 고급 설정 | 포트·반복·간격·타임아웃·프록시, CT·경로 생략·IPv6·URL 변형 생략 토글 |
| 결과 | 상태 표시줄 · 검사 환경 4칸 표 · 대상 표(상태·대상·원인 구간·조치). 행 선택 시 대상 페이지 |
| 대상 페이지 | 원인·발견 사항, 계층 진행 칩, 계층별 확장 카드, 경로 표 |
| 결과 도구 | 텍스트 복사 · 보고서 저장 · JSON 저장 · 초기화 |

사용 순서:

1. 대상 입력 (공백으로 여러 개) → 검사 범위 선택 → **실행** (또는 Enter)
2. 진행 중 상태는 왼쪽 하단과 결과 상태 표시줄에 표시, **중지**로 즉시 중단
3. 완료 후 대상 표의 행 또는 왼쪽 항목을 선택해 계층별 상세 확인
4. **보고서 저장**·**JSON 저장**으로 결과 저장

동작 구조:

```mermaid
sequenceDiagram
  participant B as 브라우저 / 앱 창
  participant S as netcheck-gui.py<br/>127.0.0.1 + 토큰
  participant E as 진단 엔진
  B->>S: GET /run?token=…&targets=…
  S->>E: run_diagnosis(sink, abort)
  loop 계층별
    E-->>S: section · row · hop 이벤트
    S-->>B: SSE (ev · line)
  end
  opt 중지
    B->>S: GET /stop → 실행 중 traceroute·ping 즉시 종료
  end
  E-->>S: 결과 (JSON · 보고서)
  S-->>B: SSE done
```

| 보안 | 내용 |
|---|---|
| 바인딩 | `127.0.0.1` 만 — 다른 기기에서 접속 불가 |
| 토큰 | 실행마다 무작위 생성, 없는 요청 거부 |
| 인자 | 허용된 옵션만 인자 리스트로 전달 (셸 미사용) |
| 동시 실행 | 1개. 새 진단 시작·연결 끊김 시 이전 진단 중단 |

---

## 9. 데스크톱 앱

GUI 를 OS 내장 웹뷰 창으로 실행 (Windows WebView2 · macOS WKWebView · Linux WebKitGTK).

```bash
pip install -r tools/requirements-app.txt
python3 tools/netcheck-app.py               # 창 실행
python3 tools/netcheck-app.py --browser     # 브라우저로 실행
python3 tools/netcheck-app.py --selftest    # 엔진·화면 로드 확인 후 종료
```

```mermaid
flowchart LR
  APP["netcheck-app.py"] --> W{"pywebview 창<br/>사용 가능?"}
  W -- 예 --> WIN["네이티브 창<br/>저장 대화상자 지원"]
  W -- 아니오 --> BR["기본 브라우저<br/>탭 종료 후 300초 뒤 자동 종료"]
  WIN --> GUI["netcheck-gui.py 서버<br/>(포트 자동 선택)"]
  BR --> GUI
  GUI --> ENG["netcheck.py 엔진"]
```

- 보고서·JSON 저장 시 OS 저장 대화상자 사용
- 창을 닫으면 실행 중인 진단을 중단하고 종료

---

## 10. 빌드 · 배포

### 로컬 빌드

```bash
pip install -r tools/requirements-app.txt
python3 tools/build-app.py
```

| OS | 결과물 | 비고 |
|---|---|---|
| macOS | `dist/netcheck.app` (약 25MB) | 서명 없음 — 첫 실행은 우클릭 → 열기 |
| Windows | `dist/netcheck.exe` | 단일 실행 파일 |
| Linux | `dist/netcheck` | 단일 실행 파일, WebKitGTK 필요 |

PyInstaller 는 교차 빌드가 안 되므로 각 OS 에서 빌드한다.

### GitHub Actions

`.github/workflows/build-app.yml` — Actions 탭에서 수동 실행하거나 `v*` 태그를 push 하면 4개 환경에서 빌드한다.

```mermaid
flowchart LR
  T["수동 실행 · v* 태그"] --> M{{"빌드 매트릭스"}}
  M --> W["windows-latest<br/>netcheck.exe"]
  M --> A["macos-14<br/>Apple Silicon .app"]
  M --> I["macos-15-intel<br/>Intel .app"]
  M --> L["ubuntu-22.04<br/>Linux 실행 파일"]
  W & A & I & L --> S["판정 시험 → 빌드 → --selftest"]
  S --> U["Artifacts 업로드"]
```

```bash
git tag v3.0 && git push origin v3.0      # 태그로 빌드
gh workflow run build-app.yml             # 수동 실행
```

---

## 11. Windows 참고

```powershell
python tools\netcheck.py api.example.com
python tools\netcheck-gui.py
```

- 명령 출력이 표시 언어로 번역되므로 레지스트리(DNS·프록시), `route print` 숫자 행, ping/tracert 의 숫자·`ms`·`TTL=` 토큰만 읽음
- `tracert` 는 ICMP 만, 홉당 3회 고정. 무응답 홉이 많으면 시간이 오래 걸림
- 콘솔 색은 Windows Terminal·PowerShell 7 에서 표시, 구형 `cmd.exe` 는 색 없음
- 회선 대조(L2b)는 인터페이스 이름 대신 주소로 표시

---

## 12. 판정 시험

가상 네트워크 상황으로 판정(근본 원인 계층·결론 문구·종료 코드)을 검증한다. 실제 네트워크를 쓰지 않는다.

```bash
python3 tools/test_verdicts.py              # 전체
python3 tools/test_verdicts.py 싱크홀        # 이름에 해당 문자열이 포함된 시나리오만
```

```
  ok   싱크홀 — DoH IP 로는 연결됨
  ok   CDN/GSLB — 응답 IP 가 달라도 같은 AS 면 정상
  ok   URL 변형 — HTTPS 실패, HTTP 응답
  ...
73 통과 / 0 실패 / 73 시나리오
```

- 시나리오 외에 stub 시그니처 일치, 대상별 판정 분리, 반복 관측, 보고서 항목, 중단 처리, 오류 코드 분류 확인 포함
- 판정 코드를 수정하면 시험을 함께 갱신

---

## 13. 문제 해결

| 증상 | 확인 |
|---|---|
| `traceroute` 결과 없음 | ICMP·UDP 차단 네트워크. L7 에 TCP 홉 거리 표시. 수동 확인: `sudo traceroute -P TCP -p 443 대상`(macOS), `sudo traceroute -T -p 443 대상`(Linux) |
| GUI 가 열리지 않음 | 터미널에 출력된 주소(토큰 포함)로 직접 접속. 포트 충돌이면 `--port` 변경 |
| 데스크톱 앱이 브라우저로 열림 | pywebview 미설치 또는 Linux WebKitGTK 없음 (`--selftest` 로 확인) |
| macOS 에서 앱이 열리지 않음 | 서명 없는 앱 — Finder 에서 우클릭 → 열기 |
| CT 조회 실패 | crt.sh 일시 장애가 잦음. 판정에는 반영하지 않음 |
| 종료 코드 `3` | 일부 계층 예외 — 출력의 `내부 오류` 줄 확인 후 이슈 등록 |
