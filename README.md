# netcheck — 계층별 도달성 진단

접속 실패를 계층(L0~L9)과 구간 단위로 검사해 실패 계층·원인 구간·조치를 출력하는 네트워크 진단 도구.

- 로컬 환경 → 게이트웨이 → 인터넷 → DNS(DoH 대조) → TCP → TLS·CT → HTTP·URL 변형 → 경로(AS·손실·역경로) → PMTU → 대조군
- 가장 얕은 계층의 치명적 실패를 근본 원인으로 판정, 대상별로 분리
- 표준 라이브러리만 사용 (Python 3.8+), macOS · Linux · Windows

## 사용

```bash
./tools/netcheck.py apis.data.go.kr                     # 단일 대상
./tools/netcheck.py -b apis.data.go.kr www.weather.go.kr  # 결론만, 여러 대상 비교
./tools/netcheck.py https://host/path?q=1                # URL (경로·스킴 그대로 사용)
./tools/netcheck.py --json host > result.json            # JSON 출력
./tools/netcheck.py --report report.md host              # Markdown 보고서
./tools/netcheck.py --watch 60 --count 30 host           # 반복 관측
./tools/netcheck.py --proxy http://proxy:3128 host       # 프록시 경유
```

종료 코드: `0` 정상 · `1` 치명적 실패 · `2` 사용법 오류 · `3` 일부 검사 중단

## GUI

```bash
./tools/netcheck-gui.py                 # 브라우저 화면 (127.0.0.1 + 토큰)

pip install -r tools/requirements-app.txt
python3 tools/netcheck-app.py           # 네이티브 창 (pywebview)
python3 tools/build-app.py              # 실행 파일 생성 (PyInstaller)
```

Windows · macOS · Linux 실행 파일은 `.github/workflows/build-app.yml` (Actions 수동 실행 또는 `v*` 태그)로 빌드.

## 시험

```bash
python3 tools/test_verdicts.py          # 가상 네트워크 시나리오로 판정 검증
```

## 구성

| 파일 | 내용 |
|---|---|
| `tools/netcheck.py` | 진단 엔진·CLI |
| `tools/netcheck-gui.py` | 로컬 웹 GUI 서버 |
| `tools/netcheck-app.py` | 데스크톱 앱 (pywebview 창) |
| `tools/build-app.py` | PyInstaller 빌드 |
| `tools/test_verdicts.py` | 판정 시험 |
| `tools/netcheck.sh` | Python 이 없는 환경용 셸 판 (기능 추가 없음) |
| `network-path-diagnosis.md` | 진단 방법·계층별 해석·사례 문서 |

문서의 예시 출력 중 사용자 회선 정보(사설 주소·ISP 경로·AS)는 문서용 예약 값(`192.168.0.x`, `203.0.113.x`, `198.51.100.x`, `AS64500`)으로 바꿔 표기함.
