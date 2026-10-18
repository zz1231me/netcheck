#!/usr/bin/env python3
# netcheck GUI — 브라우저 화면용 로컬 서버
#
#   ./tools/netcheck-gui.py            # 브라우저 자동 실행
#   ./tools/netcheck-gui.py --port 8899 --no-open
#
# 진단은 이 기기에서 실행하고 결과만 브라우저로 보낸다.
#
# 보안
#   · 127.0.0.1 에만 바인딩
#   · 실행마다 무작위 토큰 생성, 모든 요청에서 확인
#   · 클라이언트 입력은 대상과 허용된 옵션만 받아 argparse 인자 리스트로 전달 (셸 미사용)

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import queue
import re
import secrets
import socketserver
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))


def load_netcheck():
    path = os.path.join(HERE, "netcheck.py")
    if not os.path.exists(path):
        sys.exit(f"netcheck.py 없음: {path}")
    spec = importlib.util.spec_from_file_location("netcheck", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["netcheck"] = mod
    spec.loader.exec_module(mod)
    return mod


NC = load_netcheck()
TOKEN = secrets.token_urlsafe(24)
# 데스크톱 앱(pywebview) 모드. pywebview 브리지가 eval 을 쓰므로 CSP 에 unsafe-eval 추가.
APP_MODE = False
# 마지막 인증 요청 시각. 데스크톱 앱의 브라우저 대체 모드가 탭 종료를 감지하는 데 쓴다.
LAST_SEEN = 0.0

# 클라이언트가 지정할 수 있는 옵션 목록 (그 외 인자는 받지 않음)
FLAGS = {
    "quick": "-q", "full": "-f", "no_trace": "--no-trace",
    "ct": "--ct", "no_ct": "--no-ct", "ipv4": "-4", "ipv6": "-6",
    "no_variants": "--no-variants",
}
NUMS = {"port": "-p", "timeout": "-t", "repeat": "-r",
        "interval": "-i", "max_hop": "-m"}


class Aborted(BaseException):
    """진단 중단 신호. 계층별 `except Exception` 처리에 잡히지 않도록 BaseException 을 상속한다."""


class Job:
    """진단 1회 실행. 이벤트를 큐에 쌓아 SSE 로 전달한다.

    브라우저 연결이 끊기거나 중지 요청이 오면 진단을 중단한다."""

    _lock = threading.Lock()
    _jobs: dict[str, "Job"] = {}
    _active: "Job | None" = None
    # sys.stdout 은 프로세스 전역이므로 교체는 한 번에 한 작업만 한다.
    _out_lock = threading.Lock()

    def __init__(self, argv: list[str]):
        self.id = secrets.token_urlsafe(9)
        self.argv = argv
        self.q: queue.Queue = queue.Queue()
        self.done = False
        self.cancelled = False
        self.rc: int | None = None
        self.payload: dict | None = None
        self.report = ""
        self.error = ""
        self.reason = ""            # 중단 사유: user | superseded | disconnect | shutdown
        with Job._lock:
            # 동시 실행은 1개. 새 작업을 시작하면 이전 작업을 중단한다.
            if Job._active and not Job._active.done:
                Job._active.cancel("superseded")
            Job._active = self
            Job._jobs[self.id] = self
            # 오래된 작업 정리 (메모리 증가 방지)
            if len(Job._jobs) > 20:
                for k in list(Job._jobs)[:-20]:
                    Job._jobs.pop(k, None)

    @classmethod
    def get(cls, jid: str) -> "Job | None":
        with cls._lock:
            return cls._jobs.get(jid)

    def cancel(self, reason: str = "user") -> None:
        if not self.cancelled:
            self.reason = reason
        self.cancelled = True

    def _timeout(self) -> float:
        try:
            return float(self.argv[self.argv.index("-t") + 1])
        except (ValueError, IndexError):
            return 4.0

    def _abort(self) -> None:
        if self.cancelled:
            raise Aborted()

    def _tick(self, kind: str, data: dict) -> None:
        """진단 이벤트 수신. 중단 요청 여부도 여기서 확인한다."""
        if self.cancelled:
            raise Aborted()
        self.q.put(("ev", {"t": kind, **data}))

    def start(self) -> None:
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        class Pipe(io.TextIOBase):
            def __init__(self, q):
                self.q, self.buf, self.text = q, "", ""

            def write(self, sdata):
                self.text += sdata
                self.buf += sdata
                while "\n" in self.buf:
                    line, self.buf = self.buf.split("\n", 1)
                    self.q.put(("line", line))
                return len(sdata)

            def flush(self):
                pass

        # 이전 작업이 정리 중이면 종료를 기다린다 (중단 요청은 이미 전달됨).
        # 대기 시간: 이전 작업의 차단 호출(최대 약 2×타임아웃)이 끝날 여유
        if not Job._out_lock.acquire(timeout=max(30.0, 2 * self._timeout() + 10)):
            self.rc = -1 if self.cancelled else 3
            if not self.cancelled:
                self.q.put(("line", "  ✘ 이전 진단이 아직 종료 중 — 잠시 후 다시 시작"))
            self.done = True
            self.q.put(("done", self.rc))
            return
        if self.cancelled:                  # 대기 중 더 새로운 작업이 시작됨
            Job._out_lock.release()
            self.rc, self.done = -1, True
            self.q.put(("done", self.rc))
            return
        pipe = Pipe(self.q)
        nc = None
        old = sys.stdout
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):     # argparse 오류 메시지 수집
                a = NC.parse_args(self.argv)
            a.color = False
            sys.stdout = pipe
            nc, targets = NC.run_diagnosis(a, sink=self._tick, abort=self._abort)
            self.rc = nc.verdict(targets)
            self.payload = NC.to_payload(nc, targets, a)
            self.report = NC.render_report(nc, targets, a, pipe.text)
        except Aborted:
            self.rc = -1                    # 사유는 done 이벤트의 reason 으로 전달
        except SystemExit:                  # argparse 인자 오류
            lines = [ln for ln in err.getvalue().splitlines() if ln.strip()]
            msg = lines[-1].split("error:", 1)[-1].strip() if lines else "인자 확인 필요"
            self.error = f"입력 오류: {msg}"
            self.rc = 2
        except Exception as ex:
            self.error = f"{type(ex).__name__}: {ex}"
            self.rc = 3
        finally:
            sys.stdout = old
            if nc is not None:
                NC.shutdown_pool(nc.pool)
            Job._out_lock.release()
            if pipe.buf:
                self.q.put(("line", pipe.buf))
            if self.error:
                self.q.put(("line", f"  ✘ {self.error}"))
            self.done = True
            self.q.put(("done", self.rc))


PAGE = r"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netcheck — 계층별 도달성 진단</title>
<style>
/* Windows 11 Fluent 계열 토큰 */
:root{
  --bg:#f3f3f3; --side:#ebebeb; --card:#fbfbfb; --card2:#f6f6f6; --hover:#f0f0f0;
  --stroke:#e5e5e5; --stroke2:#d1d1d1; --ctrl:#ffffff; --ctrl-b:#d6d6d6; --ctrl-bb:#8a8a8a;
  --t1:#1b1b1b; --t2:#5c5c5c; --t3:#8a8a8a;
  --ac:#005fb8; --ac-h:#1a6fc1; --ac-t:#ffffff; --sel:#e3e3e3;
  --ok:#0f7b0f; --ng:#c42b1c; --wn:#9d5d00; --in:#5c5c5c;
  --okbg:#dff6dd; --ngbg:#fde7e9; --wnbg:#fff4ce; --inbg:#f0f0f0;
  --mono:"Cascadia Mono","Cascadia Code",Consolas,ui-monospace,SFMono-Regular,Menlo,monospace;
  --r:4px; --r2:7px;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#202020; --side:#1c1c1c; --card:#2b2b2b; --card2:#272727; --hover:#323232;
  --stroke:#1d1d1d; --stroke2:#3a3a3a; --ctrl:#2d2d2d; --ctrl-b:#3c3c3c; --ctrl-bb:#9a9a9a;
  --t1:#ffffff; --t2:#c5c5c5; --t3:#9a9a9a;
  --ac:#60cdff; --ac-h:#4cc2ff; --ac-t:#000000; --sel:#2d2d2d;
  --ok:#6ccb5f; --ng:#ff99a4; --wn:#fce100; --in:#c5c5c5;
  --okbg:#393d1b; --ngbg:#442726; --wnbg:#433519; --inbg:#2b2b2b;
}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--t1);
  font:14px/20px "Segoe UI Variable Text","Segoe UI",-apple-system,BlinkMacSystemFont,"Malgun Gothic","Apple SD Gothic Neo","Noto Sans KR",system-ui,sans-serif;
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--t1);outline-offset:1px}
svg.i{width:16px;height:16px;flex:none;fill:none;stroke:currentColor;stroke-width:1.4;stroke-linecap:round;stroke-linejoin:round}

/* ── 앱 셸 ── */
.app{display:grid;grid-template-columns:260px 1fr;height:100%}
.side{background:var(--side);display:flex;flex-direction:column;padding:12px 6px 10px;min-height:0;overflow:auto}
.appname{display:flex;align-items:center;gap:10px;padding:6px 12px 16px;font-size:13px;font-weight:600}
.appname .logo{width:18px;height:18px;border-radius:3px;background:var(--ac);display:grid;place-items:center}
.appname .logo i{width:6px;height:6px;border-radius:50%;background:var(--ac-t);display:block}
.appname small{font-weight:400;color:var(--t3);font-size:12px}
.nav{display:flex;align-items:center;gap:12px;width:100%;height:36px;padding:0 12px;margin:1px 0;border:0;
  border-radius:var(--r);background:transparent;cursor:pointer;text-align:left;position:relative;color:var(--t1)}
.nav:hover{background:var(--hover)}
.nav.on{background:var(--sel)}
.nav.on::before{content:"";position:absolute;left:0;top:10px;bottom:10px;width:3px;border-radius:2px;background:var(--ac)}
.nav .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13.5px}
.nav .nm.mono{font-family:var(--mono);font-size:12.5px}
.navsec{padding:16px 12px 6px;font-size:12px;font-weight:600;color:var(--t2)}
.navsec[hidden]{display:none}
.side .foot{margin-top:auto;padding:12px 12px 2px;border-top:1px solid var(--stroke2);font-size:12px;color:var(--t2);
  display:flex;align-items:center;gap:8px;min-width:0}
.side .foot .txt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

.dot{width:8px;height:8px;border-radius:50%;background:var(--t3);flex:none;opacity:.5}
.dot.run{background:var(--ac);opacity:1;animation:pulse 1s infinite}
.dot.ok{background:var(--ok);opacity:1} .dot.ng{background:var(--ng);opacity:1} .dot.wn{background:var(--wn);opacity:1}
@keyframes pulse{50%{opacity:.25}}

.content{overflow:auto;min-width:0}
.page{max-width:1080px;padding:28px 40px 60px}
.page[hidden]{display:none}
h1{font-size:28px;line-height:36px;font-weight:600;margin:0 0 4px;letter-spacing:-.01em;word-break:break-all}
.sub{color:var(--t2);margin:0 0 24px}
h2{font-size:14px;line-height:20px;font-weight:600;margin:28px 0 8px;display:flex;align-items:center;gap:8px}
h2 .meta{font-weight:400;color:var(--t2)}
h2 .tools{margin-left:auto;display:flex;gap:6px}

/* ── 카드·설정 행 ── */
.card{background:var(--card);border:1px solid var(--stroke);border-radius:var(--r2)}
.card+.card{margin-top:4px}
.row{display:flex;align-items:center;gap:16px;padding:14px 16px;min-height:62px}
.row+.row{border-top:1px solid var(--stroke)}
.row .lbl{flex:1;min-width:0}
.row .lbl b{display:block;font-weight:400}
.row .lbl span{display:block;color:var(--t2);font-size:12px;line-height:16px}
.row .ctl{flex:none;display:flex;align-items:center;gap:8px}

/* 입력 컨트롤 */
input[type=text],input[type=number],select{height:32px;padding:0 10px;background:var(--ctrl);border:1px solid var(--ctrl-b);
  border-bottom-color:var(--ctrl-bb);border-radius:var(--r);min-width:0}
input:focus,select:focus{outline:none;border-bottom:2px solid var(--ac);padding-bottom:1px}
input[type=number]{width:96px}
input.wide{width:340px}
select{padding-right:6px}
.runbar{display:grid;grid-template-columns:1fr 220px auto auto;gap:8px;padding:16px;align-items:end}
.runbar label{display:block;font-size:12px;color:var(--t2);margin-bottom:6px}
.runbar input,.runbar select{width:100%}
#t{font-family:var(--mono);font-size:13px}
.examples{padding:0 16px 14px;font-size:12px;color:var(--t2);display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.examples button{height:24px;padding:0 8px;border:1px solid var(--ctrl-b);border-radius:var(--r);background:var(--ctrl);
  font-family:var(--mono);font-size:11.5px;cursor:pointer;color:var(--t2)}
.examples button:hover{background:var(--hover)}

.btn{height:32px;padding:0 14px;border-radius:var(--r);border:1px solid var(--ctrl-b);background:var(--ctrl);cursor:pointer;
  white-space:nowrap;display:inline-flex;align-items:center;gap:8px}
.btn:hover:not(:disabled){background:var(--hover)}
.btn.ac{background:var(--ac);border-color:var(--ac);color:var(--ac-t);min-width:96px;justify-content:center}
.btn.ac:hover:not(:disabled){background:var(--ac-h)}
.btn:disabled{opacity:.45;cursor:default}
.btn.sm{height:28px;padding:0 10px;font-size:13px}

/* 토글 스위치 */
.sw{display:inline-flex;align-items:center;gap:10px;cursor:pointer;user-select:none;font-size:13px;color:var(--t2)}
.sw input{appearance:none;-webkit-appearance:none;width:40px;height:20px;border-radius:10px;margin:0;cursor:pointer;
  border:1px solid var(--ctrl-bb);background:transparent;position:relative;transition:background .1s}
.sw input::after{content:"";position:absolute;top:3px;left:3px;width:12px;height:12px;border-radius:50%;background:var(--t2);transition:left .1s}
.sw input:checked{background:var(--ac);border-color:var(--ac)}
.sw input:checked::after{left:23px;background:var(--ac-t)}
.sw .swt{min-width:16px;text-align:right}

/* 확장 카드 */
details.exp{background:var(--card);border:1px solid var(--stroke);border-radius:var(--r2)}
details.exp+details.exp{margin-top:4px}
details.exp>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:14px;padding:12px 16px;min-height:56px}
details.exp>summary::-webkit-details-marker{display:none}
details.exp>summary:hover{background:var(--hover);border-radius:var(--r2)}
details.exp>summary::after{content:"";width:7px;height:7px;border-right:1.4px solid var(--t2);border-bottom:1.4px solid var(--t2);
  transform:rotate(45deg);margin:0 4px 4px 8px;flex:none;transition:transform .12s}
details.exp[open]>summary::after{transform:rotate(-135deg);margin-bottom:-2px}
details.exp>summary .lbl{flex:1;min-width:0}
details.exp>summary .lbl b{display:block;font-weight:400}
details.exp>summary .lbl span{display:block;color:var(--t2);font-size:12px;line-height:16px}
details.exp>summary .cnt{color:var(--t2);font-size:12px}
details.exp .body{border-top:1px solid var(--stroke)}

/* 계층 코드 상자 */
.lay{font-family:var(--mono);font-size:11px;font-weight:600;width:40px;height:24px;display:grid;place-items:center;
  border-radius:var(--r);background:var(--card2);border:1px solid var(--stroke2);color:var(--t2);flex:none}
.lay.ok{color:var(--ok);border-color:var(--ok)}
.lay.ng{background:var(--ng);border-color:var(--ng);color:#fff}
.lay.wn{background:var(--wnbg);border-color:var(--wn);color:var(--wn)}
@media (prefers-color-scheme:dark){.lay.ng{color:#000}}

/* 측정값 표 */
.kv{display:grid;grid-template-columns:18px minmax(120px,200px) 1fr;column-gap:12px;padding:4px 16px 8px}
.r{display:contents}
.r>*{padding:7px 0;border-bottom:1px solid var(--stroke)}
.kv>.r:last-child>*{border-bottom:0}
.m{font-weight:700;text-align:center;font-size:13px}
.m.ok{color:var(--ok)} .m.ng{color:var(--ng)} .m.wn{color:var(--wn)} .m.info,.m.bar{color:var(--t3)}
.k{color:var(--t2);font-size:13px}
.v{word-break:break-word;min-width:0;font-size:13px}
.r.ng .v{color:var(--ng)} .r.wn .v{color:var(--wn)}
.note{grid-column:2/4;color:var(--t2);font-size:12px;padding:0 0 7px;margin-top:-3px;border-bottom:1px solid var(--stroke)}

/* 데이터 표 */
table.grid{width:100%;border-collapse:collapse;font-size:13px}
table.grid th{text-align:left;font-weight:600;font-size:12px;color:var(--t2);padding:8px 12px;border-bottom:1px solid var(--stroke2);
  white-space:nowrap;background:var(--card2)}
table.grid td{padding:9px 12px;border-bottom:1px solid var(--stroke);vertical-align:top}
table.grid tr:last-child td{border-bottom:0}
table.grid .n{text-align:right;white-space:nowrap;font-family:var(--mono);font-size:12px}
table.grid .mono{font-family:var(--mono);font-size:12px}
table.grid tbody tr.click{cursor:pointer}
table.grid tbody tr.click:hover td{background:var(--hover)}
table.grid tr.edge td{background:var(--wnbg)}
table.grid tr.dead td{color:var(--t3)}
.hopwrap{margin:0 16px 12px;border:1px solid var(--stroke);border-radius:var(--r);overflow-x:auto}
.ptr{color:var(--t3);font-size:11.5px;font-family:var(--mono)}
.tag{font-size:11px;padding:0 5px;border-radius:3px;border:1px solid var(--stroke2);color:var(--t2);margin-left:6px;white-space:nowrap}
.tag.edge{border-color:var(--wn);color:var(--wn)}
.loss{color:var(--wn);font-weight:600}

/* 상태 배지 */
.badge{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 8px;border-radius:var(--r);font-size:12px;
  font-weight:600;white-space:nowrap;border:1px solid transparent}
.badge.ok{background:var(--okbg);color:var(--ok)} .badge.ng{background:var(--ngbg);color:var(--ng)}
.badge.wn{background:var(--wnbg);color:var(--wn)} .badge.run{border-color:var(--ac);color:var(--ac)}
.badge.in{background:var(--inbg);color:var(--t2)}
td .who{font-weight:600}
td .cause{color:var(--t2);font-size:12.5px;margin-top:2px}
td ul.acts{margin:6px 0 0;padding:0;list-style:none;font-size:12.5px}
td ul.acts li::before{content:"→ ";color:var(--ac);font-weight:700}

/* InfoBar */
.ib{display:flex;gap:12px;align-items:flex-start;padding:12px 16px;border-radius:var(--r);border:1px solid var(--stroke);
  background:var(--inbg);font-size:13px}
.ib+.ib{margin-top:4px}
.ib svg{margin-top:2px;width:16px;height:16px;flex:none}
.ib.ok{background:var(--okbg);color:var(--t1)} .ib.ok svg{color:var(--ok)}
.ib.ng{background:var(--ngbg)} .ib.ng svg{color:var(--ng)}
.ib.wn{background:var(--wnbg)} .ib.wn svg{color:var(--wn)}
.ib.run svg{color:var(--ac)}
.ib b{font-weight:600;margin-right:8px}
.ib ul{margin:6px 0 0;padding:0;list-style:none}
.ib li{display:flex;gap:8px;margin-top:3px}
.ib li .lv{font-family:var(--mono);font-size:11px;font-weight:600;flex:none;width:34px;color:var(--t2)}

/* 환경 요약 */
.env{display:grid;grid-template-columns:repeat(4,1fr)}
.env>div{padding:12px 16px;border-left:1px solid var(--stroke);min-width:0}
.env>div:first-child{border-left:0}
.env .k{display:flex;align-items:center;gap:8px;font-size:12px}
.env .v{font-size:14px;font-weight:600;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.env .s{font-size:12px;color:var(--t2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* 계층 진행 */
.pipe{display:flex;flex-wrap:wrap;gap:4px;margin:0 0 16px}
.st{display:inline-flex;align-items:center;gap:6px;height:26px;padding:0 9px;border-radius:var(--r);border:1px solid var(--stroke2);
  background:var(--card);font-size:12px;cursor:pointer;color:var(--t2)}
.st b{font-family:var(--mono);font-size:11px;font-weight:600}
.st.run{border-color:var(--ac);color:var(--ac)}
.st.ok b{color:var(--ok)} .st.ng{border-color:var(--ng);color:var(--ng)} .st.wn{border-color:var(--wn);color:var(--wn)}
.st.done b{color:var(--t1)}

pre.out{font-family:var(--mono);font-size:12px;line-height:18px;white-space:pre-wrap;margin:0;padding:14px 16px;
  max-height:calc(100vh - 200px);overflow:auto;color:var(--t2)}

/* 계층 안내 */
.legend{display:grid;grid-template-columns:repeat(2,1fr)}
.legend div{display:flex;gap:12px;align-items:center;padding:9px 16px;border-top:1px solid var(--stroke);font-size:13px}
.legend div:nth-child(-n+2){border-top:0}
.legend div:nth-child(odd){border-right:1px solid var(--stroke)}
.legend span{color:var(--t2);font-size:12px}

@media(max-width:860px){
  .app{grid-template-columns:1fr;grid-template-rows:auto 1fr}
  .side{flex-direction:row;flex-wrap:wrap;align-items:center;gap:2px;padding:6px;overflow:visible}
  .side .appname{padding:6px 8px}
  .side .navsec,.side .foot{display:none}
  #navList,#navUnits{display:contents}
  .nav{width:auto;height:32px}
  .page{padding:20px 16px 48px}
  .runbar{grid-template-columns:1fr auto auto}
  .runbar>div:first-child{grid-column:1/-1}
  .env{grid-template-columns:1fr 1fr}
  .env>div:nth-child(3){border-left:0}
  .env>div:nth-child(n+3){border-top:1px solid var(--stroke)}
  .legend{grid-template-columns:1fr}
  .legend div:nth-child(2){border-top:1px solid var(--stroke)}
  .legend div:nth-child(odd){border-right:0}
  input.wide{width:200px}
  .kv{grid-template-columns:16px 110px 1fr}
  .row{flex-wrap:wrap}
}
</style></head><body>
<div class="app">
  <nav class="side" aria-label="탐색">
    <div class="appname"><span class="logo"><i></i></span>netcheck <small>v3.0</small></div>
    <div id="navList">
      <button class="nav on" id="nav-home" data-k="home">
        <svg class="i" viewBox="0 0 16 16"><path d="M5 3.5l7 4.5-7 4.5z"/></svg><span class="nm">진단</span></button>
      <div class="navsec" id="navsec" hidden>결과</div>
      <div id="navUnits" role="tablist" aria-label="상세 결과"></div>
    </div>
    <div class="foot"><span id="sideDot" class="dot"></span><span class="txt" id="sideTxt">대기</span></div>
  </nav>

  <main class="content" id="content">
    <section class="page" id="page-home">
      <h1>네트워크 진단</h1>
      <p class="sub">이 기기에서 계층별로 연결을 검사하고 실패 계층과 원인 구간을 표시함</p>

      <div class="card">
        <div class="runbar">
          <div><label for="t">대상 — 공백으로 구분 (호스트 · 호스트:포트 · URL)</label>
            <input id="t" type="text" placeholder="apis.data.go.kr www.weather.go.kr" autofocus autocomplete="off" spellcheck="false"></div>
          <div><label for="md">검사 범위</label><select id="md">
            <option value="normal">기본 — 경로 포함</option>
            <option value="quick">빠른 검사 — 경로 생략</option>
            <option value="full">전체 — 포트·PMTU·CT</option></select></div>
          <button id="go" class="btn ac">실행</button>
          <button id="stop" class="btn" disabled>중지</button>
        </div>
        <div class="examples">예시
          <button data-ex="www.google.com">www.google.com</button>
          <button data-ex="apis.data.go.kr www.weather.go.kr">apis.data.go.kr www.weather.go.kr</button>
          <button data-ex="1.1.1.1:81">1.1.1.1:81</button>
        </div>
      </div>

      <details class="exp" id="adv" style="margin-top:4px">
        <summary><svg class="i" viewBox="0 0 16 16"><path d="M2 4h7M12 4h2M2 12h2M7 12h7"/><circle cx="10.5" cy="4" r="1.5"/><circle cx="5.5" cy="12" r="1.5"/></svg>
          <span class="lbl"><b>고급 설정</b><span id="advSum">기본값</span></span></summary>
        <div class="body">
          <div class="row"><div class="lbl"><b>기본 포트</b><span>포트를 지정하지 않은 대상에 사용</span></div>
            <div class="ctl"><input id="p" type="number" value="443" min="1" max="65535"></div></div>
          <div class="row"><div class="lbl"><b>TCP 반복</b><span>대상 IP 마다 연결 시도 횟수 — 간헐 장애 확인</span></div>
            <div class="ctl"><input id="r" type="number" value="3" min="1" max="50"></div></div>
          <div class="row"><div class="lbl"><b>반복 간격(초)</b><span>연결 시도 사이 대기 시간</span></div>
            <div class="ctl"><input id="iv" type="number" value="0" min="0" max="600"></div></div>
          <div class="row"><div class="lbl"><b>타임아웃(초)</b><span>연결·응답 대기 한도</span></div>
            <div class="ctl"><input id="to" type="number" value="4" min="1" max="60"></div></div>
          <div class="row"><div class="lbl"><b>프록시</b><span>비우면 직접 연결. http:// · socks5:// · socks5h:// (socks5h 는 이름 해석도 프록시에서)</span></div>
            <div class="ctl"><input id="px" class="wide" type="text" placeholder="http://proxy.corp:3128" spellcheck="false"></div></div>
          <div class="row"><div class="lbl"><b>CT 로그 대조</b><span>crt.sh 로 인증서 발급 이력 확인 — 도메인 이름이 crt.sh 로 전송됨</span></div>
            <div class="ctl"><label class="sw"><span class="swt">끔</span><input type="checkbox" id="ct"></label></div></div>
          <div class="row"><div class="lbl"><b>경로 추적 생략</b><span>traceroute(L7·L7b) 생략 — 검사 시간 단축</span></div>
            <div class="ctl"><label class="sw"><span class="swt">끔</span><input type="checkbox" id="nt"></label></div></div>
          <div class="row"><div class="lbl"><b>IPv6 로 검사</b><span>AAAA 레코드·IPv6 경로로만 검사 (-6)</span></div>
            <div class="ctl"><label class="sw"><span class="swt">끔</span><input type="checkbox" id="v6"></label></div></div>
          <div class="row"><div class="lbl"><b>URL 변형 확인 생략</b><span>https·http × www 유무 조합 요청(L6b) 생략</span></div>
            <div class="ctl"><label class="sw"><span class="swt">끔</span><input type="checkbox" id="nv"></label></div></div>
        </div>
      </details>

      <div id="empty">
        <h2>검사 계층</h2>
        <div class="card legend" id="legend"></div>
      </div>

      <div id="result" hidden>
        <h2>결과 <span class="meta" id="meta"></span>
          <span class="tools">
            <button class="btn sm" id="copy" disabled>텍스트 복사</button>
            <button class="btn sm" id="rp" disabled>보고서 저장</button>
            <button class="btn sm" id="exp" disabled>JSON 저장</button>
            <button class="btn sm" id="clr">초기화</button>
          </span></h2>
        <div id="status" role="status" aria-live="polite"></div>
        <div id="envwrap" hidden>
          <h2>검사 환경</h2>
          <div class="card env" id="env"></div>
          <div id="envmsg"></div>
        </div>
        <h2>대상</h2>
        <div class="card" style="overflow-x:auto"><table class="grid">
          <thead><tr><th style="width:120px">상태</th><th style="width:30%">대상</th><th>원인 구간 · 조치</th></tr></thead>
          <tbody id="verdict"></tbody></table></div>
      </div>
    </section>
    <div id="panes"></div>
  </main>
</div>

<script>
// 구형 엔진(IE 계열 등) 확인 — ES5 문법만 사용
(function(){
  if(!window.EventSource||!window.fetch||!window.Promise||!window.Map){
    document.body.innerHTML='<p style="padding:24px;font:15px sans-serif">이 화면은 최신 웹 엔진이 필요함 (Windows: WebView2 런타임 설치, 또는 --browser 로 실행).</p>';
    throw new Error("unsupported engine");
  }
})();
</script>
<script>
const $=i=>document.getElementById(i), TOKEN=new URLSearchParams(location.search).get("token")||"";
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const LN={L0:"로컬 환경",L1:"게이트웨이",L2:"인터넷",L2b:"회선 대조",L2c:"프록시",L3:"DNS",L3b:"도메인",
  L4:"TCP",L4b:"목적지 정보",L5:"TLS",L5b:"인증서 이력",L6:"HTTP",L6b:"URL 변형",L7:"경로",L7b:"경로 비교",L8:"PMTU",L9:"대조군"};
const LD={L0:"기본 경로·공인 IP·NAT·VPN·프록시",L1:"공유기까지 손실·지연",L2:"DNS 없이 IP 로 외부 연결",
  L2b:"회선별 연결 결과",L2c:"직접 연결과 프록시 연결 비교",L3:"시스템 DNS 와 DoH 응답 비교",L3b:"등록 상태·권위 서버",
  L4:"포트 연결과 실패 유형",L4b:"소유자·대역·RPKI",L5:"핸드셰이크·인증서·SNI",L5b:"CT 로그 발급 이력",
  L6:"응답 코드·시간·리다이렉트",L6b:"https·http × www 조합",L7:"홉별 소유자·손실",L7b:"정상 대조군과 분기 지점",
  L8:"큰 패킷 통과 여부",L9:"정상이어야 할 목적지"};
const MARK={ok:"✔",ng:"✘",wn:"⚠",info:"·",blame:"→",bar:"━"};
const IC={
  env:'<svg class="i" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12"/></svg>',
  target:'<svg class="i" viewBox="0 0 16 16"><rect x="2.5" y="3" width="11" height="4" rx="1"/><rect x="2.5" y="9" width="11" height="4" rx="1"/><path d="M5 5h.01M5 11h.01"/></svg>',
  raw:'<svg class="i" viewBox="0 0 16 16"><path d="M4 2h5l3 3v9H4z"/><path d="M9 2v3h3M6 8h4M6 10.5h4"/></svg>',
  json:'<svg class="i" viewBox="0 0 16 16"><path d="M6 3C4 3 5 7 3 8c2 1 1 5 3 5M10 3c2 0 1 4 3 5-2 1-1 5-3 5"/></svg>',
  ok:'<svg viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="8" r="7"/><path d="M5 8.2l2 2 4-4.2" style="stroke:var(--card)" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  ng:'<svg viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="8" r="7"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5" style="stroke:var(--card)" stroke-width="1.6" stroke-linecap="round"/></svg>',
  wn:'<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5l7 12.5H1z"/><path d="M8 6v3.5M8 11.6v.1" style="stroke:var(--card)" stroke-width="1.6" stroke-linecap="round"/></svg>',
  run:'<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="8" cy="8" r="6" stroke-dasharray="28 10"/></svg>',
  in:'<svg viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="8" r="7"/><path d="M8 7v4.5M8 4.6v.1" style="stroke:var(--card)" stroke-width="1.6" stroke-linecap="round"/></svg>'};
// done: 실행 완료, 판정 표시(✔·✘·⚠) 없음
const RANK={"":0,run:1,done:2,ok:3,wn:4,ng:5};
const ENV="env";                       // 내부 키. 대상 키는 "t:" 접두사로 구분
const tk=k=>"t:"+k;
let es=null, raw="", payload=null, report="", jobId=null, t0=0;
// units: 내부 키 → 단위(검사 환경·대상). tabs: 내부 키 → {tab,pane} (원본·JSON 포함)
let units=new Map(), tabs=new Map(), cur=null, curSec=null, hopTable=null, inVerdict=false;

/* ── 상태 표시 (사이드바 하단 + 결과 InfoBar) ── */
function setStatus(cls,text,detail){
  $("sideDot").className="dot "+cls; $("sideTxt").textContent=text;
  if(!cls&&!detail){$("status").innerHTML="";return}
  const ic=IC[cls]||IC.in;
  $("status").innerHTML=`<div class="ib ${cls||""}">${ic}<div><b>${esc(text)}</b>${detail?esc(detail):""}</div></div>`;
}

/* ── 페이지 전환 ── */
function addTab(key,label,kind){
  const n=tabs.size;
  const tab=document.createElement("button");
  tab.className="nav"; tab.id="tab-"+n;
  tab.setAttribute("role","tab"); tab.setAttribute("aria-selected","false");
  tab.setAttribute("aria-controls","pane-"+n); tab.tabIndex=-1;
  const mono=kind==="target";
  tab.innerHTML=IC[kind]+`<span class="nm${mono?" mono":""}">${esc(label)}</span>`+
    (kind==="env"||kind==="target"?`<span class="dot run"></span>`:"");
  tab.onclick=()=>show(key);
  const pane=document.createElement("section");
  pane.className="page"; pane.id="pane-"+n; pane.hidden=true;
  pane.setAttribute("role","tabpanel"); pane.setAttribute("aria-labelledby",tab.id);
  $("navUnits").appendChild(tab); $("panes").appendChild(pane);
  $("navsec").hidden=false;
  const t={key,tab,pane}; tabs.set(key,t); return t;
}
function show(key){
  const home=key==="home";
  $("page-home").hidden=!home; $("nav-home").classList.toggle("on",home);
  for(const [k,t] of tabs){
    const on=k===key;
    t.tab.classList.toggle("on",on); t.tab.setAttribute("aria-selected",on);
    t.tab.tabIndex=on?0:-1; t.pane.hidden=!on;
  }
  $("content").scrollTop=0;
}
$("nav-home").onclick=()=>show("home");
$("navUnits").addEventListener("keydown",e=>{
  if(!["ArrowUp","ArrowDown","Home","End"].includes(e.key))return;
  const keys=[...tabs.keys()], i=keys.findIndex(k=>tabs.get(k).tab===document.activeElement);
  if(i<0)return;
  const j=e.key==="Home"?0:e.key==="End"?keys.length-1:(i+(e.key==="ArrowDown"?1:-1)+keys.length)%keys.length;
  show(keys[j]); tabs.get(keys[j]).tab.focus(); e.preventDefault();
});

/* ── 단위(검사 환경 / 대상) ── */
function unit(key,label){
  if(units.has(key))return units.get(key);
  const env=key===ENV;
  const {tab,pane}=addTab(key,label,env?"env":"target");
  pane.innerHTML=`<h1${env?"":' style="font-family:var(--mono);font-size:24px"'}>${esc(label)}</h1>`+
    `<p class="sub">${env?"대상과 무관한 공통 검사 (L0·L1·L2·L9)":"계층별 측정값"}</p>`+
    `<div class="sum"></div><div class="pipe"></div><div class="secs"></div>`;
  const u={key,label,layers:{},state:"run",tab,pane,sum:pane.querySelector(".sum"),
    pipe:pane.querySelector(".pipe"),secs:pane.querySelector(".secs"),row:null};
  units.set(key,u);
  if(!env)liveRow(u);
  return u;
}
function paint(u,l,cls){
  if(RANK[cls]<RANK[u.layers[l]||""])return;
  u.layers[l]=cls;
  let chip=[...u.pipe.children].find(c=>c.dataset.l===l);
  if(!chip){
    chip=document.createElement("button");
    chip.dataset.l=l; chip.title=`${l} ${LN[l]||""}`;
    chip.innerHTML=`<b>${esc(l)}</b>${esc(LN[l]||"")}`;
    chip.onclick=()=>{const s=[...u.secs.children].find(x=>x.dataset.l===l);
      if(s){s.open=true;s.scrollIntoView({behavior:"smooth",block:"start"})}};
    u.pipe.appendChild(chip);
  }
  chip.className="st "+cls;
  const sec=[...u.secs.children].find(x=>x.dataset.l===l);
  if(sec)sec.querySelector(".lay").className="lay "+(cls==="run"||cls==="done"?"":cls);
  setDot(u);
  if(u.row&&u.state==="run")liveRow(u);
}
function setDot(u){
  const worst=Object.values(u.layers).reduce((a,c)=>RANK[c]>RANK[a]?c:a,"");
  const cls=(worst==="ng"||worst==="wn")?worst:({run:"run",ok:"ok",wn:"wn",ng:"ng"}[u.state]||"");
  const d=u.tab&&u.tab.querySelector(".dot"); if(d)d.className="dot "+cls;
}
function settle(u){
  if(!u)return;
  for(const [l,c] of Object.entries(u.layers))if(c==="run")paint(u,l,"done");
}

/* ── 이벤트 처리 ── */
function section(layer,title){
  if(!cur)cur=unit(ENV,"검사 환경");
  settle(cur);
  const d=document.createElement("details");
  d.className="exp"; d.open=true; d.dataset.l=layer;
  const sub=title.replace(/^\S+\s*·\s*/,"");
  d.innerHTML=`<summary><span class="lay">${esc(layer)}</span>`+
    `<span class="lbl"><b>${esc(sub.split(" — ")[0])}</b><span>${esc(sub.split(" — ").slice(1).join(" — "))}</span></span>`+
    `<span class="cnt"></span></summary><div class="body"><div class="kv"></div></div>`;
  cur.secs.appendChild(d); curSec=d; hopTable=null;
  paint(cur,layer,"run");
  setStatus("run",`진단 중 · ${cur.label} · ${layer} ${LN[layer]||""}`,"");
}
function addRow(mark,label,text){
  if(!curSec&&cur&&cur.key!==ENV&&!inVerdict)section("L4","L4 · 대상 지정 — 입력 확인");
  if(!curSec)return;
  const div=document.createElement("div");
  div.className="r "+mark;
  div.innerHTML=`<span class="m ${mark}">${MARK[mark]||"·"}</span><span class="k">${esc(label)}</span>`+
    `<span class="v">${esc(text)}</span>`;
  curSec.querySelector(".kv").appendChild(div);
  if(mark==="ng"||mark==="wn"||mark==="ok")paint(cur,curSec.dataset.l,mark);
}
function addNote(text){
  if(!curSec)return;
  const d=document.createElement("div"); d.className="note"; d.textContent=text;
  curSec.querySelector(".kv").appendChild(d);
}
function addHop(h){
  if(!curSec)return;
  if(!hopTable){
    const w=document.createElement("div"); w.className="hopwrap";
    w.innerHTML=`<table class="grid"><thead><tr><th class="n">홉</th><th>주소</th><th class="n">RTT(ms)</th>`+
      `<th class="n">증가</th><th class="n">응답</th><th>AS</th><th>소유자</th></tr></thead><tbody></tbody></table>`;
    curSec.querySelector(".body").appendChild(w);
    hopTable=w.querySelector("tbody");
  }
  const tr=document.createElement("tr");
  if(h.ip==="*"){
    tr.className="dead";
    tr.innerHTML=`<td class="n">${esc(h.n)}</td><td colspan="6">* 무응답 (라우터의 ICMP 미응답일 수 있음)</td>`;
  }else{
    if(h.edge)tr.className="edge";
    const loss=h.sent&&h.recv<h.sent;
    tr.innerHTML=`<td class="n">${esc(h.n)}</td>`+
      `<td><span class="mono">${esc(h.ip)}</span>${h.ptr?`<div class="ptr">${esc(h.ptr)}</div>`:""}</td>`+
      `<td class="n">${h.rtt!=null?Number(h.rtt).toFixed(2):"–"}</td>`+
      `<td class="n">${esc(h.delta||"")}</td>`+
      `<td class="n${loss?" loss":""}">${esc(h.recv)}/${esc(h.sent)}</td>`+
      `<td class="mono">${h.asn!=="-"?"AS"+esc(h.asn):"–"}</td>`+
      `<td>${esc(h.owner)}${h.ecmp?'<span class="tag">ECMP</span>':""}${h.edge?'<span class="tag edge">AS 경계</span>':""}</td>`;
  }
  hopTable.appendChild(tr);
}

/* ── 요약 표 ── */
function rowEl(u){
  if(!u.row){
    u.row=document.createElement("tr");
    $("verdict").appendChild(u.row);
  }
  if(units.has(u.key)){u.row.className="click";u.row.onclick=()=>show(u.key)}
  return u.row;
}
function liveRow(u){
  const r=rowEl(u);
  const bad=Object.entries(u.layers).filter(([,s])=>s==="ng").map(([l])=>l);
  const last=Object.keys(u.layers).slice(-1)[0];
  r.innerHTML=`<td>${bad.length?`<span class="badge ng">${esc(bad[0])} 실패 감지</span>`:`<span class="badge run">검사 중</span>`}</td>`+
    `<td class="mono">${esc(u.label)}</td>`+
    `<td><span class="cause">${last?esc(`${last} ${LN[last]||""}`):"대기"} 진행 중</span></td>`;
}
function finalRow(u,t,fs){
  const r=rowEl(u);
  const crit=fs.filter(x=>x.level==="CRIT"), warn=fs.filter(x=>x.level==="WARN");
  const cls=t.root_layer?"ng":(warn.length?"wn":"ok");
  u.state=cls;
  const badge=t.root_layer?`${t.root_layer} ${LN[t.root_layer]||""}`:(warn.length?`경고 ${warn.length}`:"정상");
  const who=t.root_layer?(t.who||t.root_layer):(warn.length?"문제 없음 — 경고 있음":"문제 없음 — 전 계층 통과");
  let h=`<td><span class="badge ${cls}">${esc(badge)}</span></td><td class="mono">${esc(u.label)}</td>`+
    `<td><div class="who">${esc(who)}</div>`;
  if(t.root_layer&&t.cause)h+=`<div class="cause">${esc(t.cause)}</div>`;
  if(t.root_layer&&(t.actions||[]).length)h+=`<ul class="acts">${t.actions.map(a=>`<li>${esc(a)}</li>`).join("")}</ul>`;
  h+=`</td>`;
  r.innerHTML=h;
  // 상세 페이지 상단 요약
  if(u.sum){
    const item=x=>`<li><span class="lv">${esc(x.layer)}</span><span>${esc(x.message)}</span></li>`;
    const list=[...crit,...warn];
    u.sum.innerHTML=`<div class="ib ${cls}">${IC[cls]}<div><b>${esc(who)}</b>`+
      `${t.root_layer&&t.cause?esc(t.cause):""}`+
      `${list.length?`<ul>${list.map(item).join("")}</ul>`:""}</div></div><div style="height:16px"></div>`;
  }
  setDot(u);
  return cls;
}
function envStrip(){
  const p=payload||{}, loc=p.local||{}, inet=p.internet||{}, base=p.baseline||{};
  const e=units.get(ENV)||{layers:{}};
  const st=l=>{const s=e.layers[l]||"";return s==="run"||s==="done"?"":s};
  const cell=(l,v,s)=>`<div><div class="k"><span class="dot ${st(l)}"></span>${esc(LN[l])}</div>`+
    `<div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`;
  $("envwrap").hidden=false;
  $("env").innerHTML=
    cell("L0",loc.public_ip||loc.address||"–",`공인 IP · 로컬 ${loc.address||"?"} · MTU ${loc.mtu||"?"}`)+
    cell("L1",loc.gateway||"없음",`게이트웨이 · ${loc.interface||""}`)+
    cell("L2",inet.tried?`${inet.up}/${inet.tried} 연결`:"–","DNS 없이 IP 로 연결")+
    cell("L9",base.total?`${base.up}/${base.total} 정상`:"–","대조군 연결");
  const fs=(p.findings||[]).filter(x=>!x.target&&x.level!=="INFO");
  $("envmsg").innerHTML=fs.map(x=>{const c=x.level==="CRIT"?"ng":"wn";
    return `<div class="ib ${c}" style="margin-top:4px">${IC[c]}<div><b>${esc(x.layer)}</b>${esc(x.message)}</div></div>`}).join("");
}
const STOP_TEXT={"-1":"중단됨","-2":"연결 끊김"};
const REASON={superseded:"다른 진단이 시작되어 중단됨",shutdown:"서버 종료로 중단됨"};
function showVerdict(rc,reason){
  const sec=((Date.now()-t0)/1000).toFixed(1);
  if(!payload&&STOP_TEXT[rc]){
    for(const u of units.values()){
      if(!u.row||u.state!=="run")continue;
      const b=u.row.querySelector(".badge"); if(b){b.className="badge wn";b.textContent=STOP_TEXT[rc]}
      const c=u.row.querySelector(".cause"); if(c)c.textContent=c.textContent.replace("진행 중","단계에서 중단");
    }
    setStatus("wn",rc===-2?"연결 끊김":(REASON[reason]||"중단됨"),
      rc===-2?` — 서버 응답 없음 · ${sec}초`:` — ${sec}초`);
    return;
  }
  if(!payload){
    const errs=raw.split("\n").filter(l=>l.trim().startsWith("✘")).map(l=>l.trim().replace(/^✘\s*/,""));
    for(const u of units.values())if(u.row){u.row.remove();u.row=null}
    $("verdict").innerHTML=`<tr><td><span class="badge ng">실행 실패</span></td><td colspan="2">${esc(errs.join(" · ")||"결과 없음")}</td></tr>`;
    setStatus("ng","실행 실패",errs.length?" — "+errs[0]:"");
    return;
  }
  envStrip();
  const ts=payload.targets||[], inv=payload.invalid_targets||[], fs=payload.findings||[];
  let ng=0, wn=0, ok=0;
  for(const t of [...inv,...ts]){
    const key=t.key||t.host;
    const u=units.get(tk(key))||{key:tk(key),label:key,layers:{},state:"run",row:null,sum:null};
    const c=finalRow(u,t,fs.filter(x=>x.target===key));
    c==="ng"?ng++:c==="wn"?wn++:ok++;
  }
  const parts=[ng&&`실패 ${ng}`,wn&&`경고 ${wn}`,ok&&`정상 ${ok}`].filter(Boolean).join(" · ");
  const cls=ng?"ng":(wn||rc===3)?"wn":"ok";
  setStatus(cls,`완료 · ${parts||"대상 없음"}`,` — ${sec}초`+(rc===3?" · 일부 검사 중단":"")+
    (ng?" · 행을 선택하면 계층별 상세 표시":""));
  $("meta").textContent=parts?`${parts} · ${sec}초`:"";
}

/* ── 실행 ── */
function resetUI(){
  units=new Map();tabs=new Map();cur=null;curSec=null;hopTable=null;inVerdict=false;
  raw="";payload=null;report="";jobId=null;
  $("verdict").innerHTML="";$("env").innerHTML="";$("envmsg").innerHTML="";$("envwrap").hidden=true;
  $("navUnits").innerHTML="";$("panes").innerHTML="";$("meta").textContent="";$("navsec").hidden=true;
  $("result").hidden=true;$("empty").hidden=false;
  setStatus("","대기"); show("home");
}
function extraTabs(){
  for(const [key,label,kind,body] of [["x:raw","원본 출력","raw",raw],
      ["x:json","JSON","json",payload?JSON.stringify(payload,null,2):""]]){
    if(!body)continue;
    const {pane}=addTab(key,label,kind);
    pane.innerHTML=`<h1>${esc(label)}</h1><p class="sub">${kind==="raw"?"CLI 와 같은 텍스트 출력":"구조화 결과 (--json 과 같은 형식)"}</p>`+
      `<div class="card"><pre class="out"></pre></div>`;
    pane.querySelector("pre").textContent=body;
  }
}
function args(){
  const q=new URLSearchParams({token:TOKEN,targets:$("t").value.trim(),port:$("p").value,repeat:$("r").value,
    timeout:$("to").value,interval:$("iv").value,proxy:$("px").value.trim()});
  const md=$("md").value;
  if(md==="quick")q.set("quick","1"); if(md==="full")q.set("full","1");
  if($("ct").checked)q.set("ct","1"); else if(md==="full")q.set("no_ct","1");
  if($("nt").checked)q.set("no_trace","1");
  if($("v6").checked)q.set("ipv6","1");
  if($("nv").checked)q.set("no_variants","1");
  return q;
}
function busy(on){
  $("go").disabled=on;$("stop").disabled=!on;
  for(const id of ["copy","rp","exp"])$(id).disabled=true;
}
function start(){
  if(!$("t").value.trim()){$("t").focus();return}
  if(es){stopJob();es.close();es=null}
  resetUI();
  $("empty").hidden=true;$("result").hidden=false;
  t0=Date.now(); busy(true); setStatus("run","진단 준비 중",""); $("stop").focus();
  cur=unit(ENV,"검사 환경");
  es=new EventSource("/run?"+args());
  es.addEventListener("line",ev=>{raw+=JSON.parse(ev.data)+"\n"});
  es.addEventListener("job",ev=>{jobId=JSON.parse(ev.data).id});
  es.addEventListener("ev",ev=>{
    const d=JSON.parse(ev.data);
    if(d.t==="target"){
      settle(cur); const e=units.get(ENV); if(e){e.state="ok";setDot(e)}
      const key=d.key||d.host;
      const label=(key!==d.host||!d.port)?key:(String(d.host).includes(":")?`[${d.host}]:${d.port}`:`${d.host}:${d.port}`);
      cur=unit(tk(key),label); curSec=null; inVerdict=false;
    }
    else if(d.t==="section"){
      if(d.layer==="판정"){curSec=null;inVerdict=true} else section(d.layer,d.title);
    }
    else if(d.t==="row")addRow(d.mark,d.label,d.text);
    else if(d.t==="note")addNote(d.text);
    else if(d.t==="hop")addHop(d);
  });
  es.addEventListener("done",ev=>{
    const d=JSON.parse(ev.data); payload=d.payload; report=d.report||""; finish(d.rc,d.reason);
  });
  es.onerror=()=>{if(!es)return; stopJob(); finish(-2)};
}
function finish(rc,reason){
  if(es){es.close();es=null}
  const hadFocus=document.activeElement===$("stop")||document.activeElement===document.body;
  busy(false);
  for(const u of units.values()){
    settle(u);
    for(const s of u.secs.querySelectorAll("details.exp")){
      const n=s.querySelectorAll(".r").length; s.querySelector(".cnt").textContent=n?`${n}항목`:"";
      const st=u.layers[s.dataset.l]||"";
      s.querySelector(".lay").className="lay "+(st==="run"||st==="done"?"":st);
      s.open=st==="ng"||st==="wn";
    }
  }
  const e=units.get(ENV); if(e)e.state="ok";
  showVerdict(rc,reason);
  for(const u of units.values()){if(u.state==="run")u.state="wn"; setDot(u)}
  for(const [k,u] of [...units])if(!u.secs.children.length&&!u.row){
    u.tab.remove();u.pane.remove();units.delete(k);tabs.delete(k);
  }
  extraTabs();
  $("copy").disabled=!raw; $("exp").disabled=!payload; $("rp").disabled=!report;
  if(hadFocus)$("go").focus();
}

/* ── 저장·복사 ── */
function flash(id,text){
  const b=$(id), old=b.dataset.label||b.textContent;
  b.dataset.label=old; b.textContent=text; setTimeout(()=>b.textContent=old,1400);
}
// 데스크톱 앱(pywebview)이면 네이티브 저장 대화상자, 브라우저면 다운로드
function save(name,text,type,id){
  const api=window.pywebview&&window.pywebview.api;
  if(api&&api.save_file){
    api.save_file(name,text).then(p=>{if(p)flash(id,"저장됨")}).catch(()=>flash(id,"저장 실패"));
    return;
  }
  const b=new Blob([text],{type}), a=document.createElement("a");
  a.href=URL.createObjectURL(b); a.download=name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href),10000);
}
function copyFallback(text){
  const ta=document.createElement("textarea");
  ta.value=text; ta.style.position="fixed"; ta.style.opacity="0";
  document.body.appendChild(ta); ta.select();
  const ok=document.execCommand("copy"); ta.remove();
  return ok?Promise.resolve():Promise.reject();
}
function copyText(text){
  if(navigator.clipboard&&window.isSecureContext)
    return navigator.clipboard.writeText(text).catch(()=>copyFallback(text));
  return copyFallback(text);
}
const stamp=()=>new Date().toISOString().slice(0,19).replace(/[:T]/g,"");
function stopJob(){
  if(jobId)fetch(`/stop?token=${encodeURIComponent(TOKEN)}&job=${encodeURIComponent(jobId)}`).catch(()=>{});
}

/* ── 고급 설정 요약·토글 표시 ── */
const DEF={p:"443",r:"3",iv:"0",to:"4",px:""};
function advSummary(){
  const ch=[];
  if($("p").value!==DEF.p)ch.push(`포트 ${$("p").value}`);
  if($("r").value!==DEF.r)ch.push(`반복 ${$("r").value}`);
  if($("iv").value!==DEF.iv)ch.push(`간격 ${$("iv").value}초`);
  if($("to").value!==DEF.to)ch.push(`타임아웃 ${$("to").value}초`);
  if($("px").value.trim())ch.push("프록시");
  if($("ct").checked)ch.push("CT");
  if($("nt").checked)ch.push("경로 생략");
  if($("v6").checked)ch.push("IPv6");
  if($("nv").checked)ch.push("URL 변형 생략");
  $("advSum").textContent=ch.length?ch.join(" · "):"기본값";
  document.querySelectorAll(".sw").forEach(l=>{l.querySelector(".swt").textContent=l.querySelector("input").checked?"켬":"끔"});
}

/* ── 연결 ── */
$("go").onclick=start;
$("stop").onclick=()=>{stopJob();finish(-1)};
$("copy").onclick=()=>copyText(raw).then(()=>flash("copy","복사됨"),()=>flash("copy","복사 실패"));
$("exp").onclick=()=>save(`netcheck-${stamp()}.json`,JSON.stringify(payload,null,2),"application/json","exp");
$("rp").onclick=()=>save(`netcheck-${stamp()}.md`,report,"text/markdown;charset=utf-8","rp");
$("clr").onclick=()=>{
  if(es){stopJob();es.close();es=null}
  resetUI(); busy(false);
  for(const [id,v] of Object.entries({t:"",md:"normal",...DEF}))$(id).value=v;
  for(const id of ["ct","nt","v6","nv"])$(id).checked=false;
  advSummary(); $("t").focus();
};
// 한글 등 IME 조합 중 Enter 는 무시
$("t").addEventListener("keydown",e=>{
  if(e.key==="Enter"&&!e.isComposing&&e.keyCode!==229&&!$("go").disabled)start();
});
document.querySelectorAll("[data-ex]").forEach(b=>b.onclick=()=>{$("t").value=b.dataset.ex;$("t").focus()});
for(const id of ["p","r","iv","to","px","ct","nt","v6","nv"]){
  $(id).addEventListener("input",advSummary); $(id).addEventListener("change",advSummary);
}
$("legend").innerHTML=Object.keys(LN).map(l=>`<div><span class="lay">${l}</span><b style="font-weight:400">${LN[l]}</b><span>${LD[l]}</span></div>`).join("");
// 페이지가 열려 있음을 서버에 알림 (브라우저 모드에서 탭 종료 감지용)
setInterval(()=>fetch(`/ping?token=${encodeURIComponent(TOKEN)}`).catch(()=>{}),20000);
advSummary(); resetUI();
</script></body></html>
"""


def build_argv(qs: dict[str, list[str]]) -> list[str]:
    """질의 문자열을 netcheck 인자 리스트로 변환한다. 허용된 옵션만 쓰며 값 검증은 argparse 가 한다."""
    argv: list[str] = []
    for key, flag in NUMS.items():
        v = (qs.get(key) or [""])[0].strip()
        if v:
            if not re.fullmatch(r"\d+(\.\d+)?", v):
                raise ValueError(f"{key} 는 0 이상의 숫자여야 함: {v!r}")
            argv += [flag, v]
    for key, flag in FLAGS.items():
        if (qs.get(key) or [""])[0] in ("1", "true", "on"):
            argv.append(flag)
    px = (qs.get("proxy") or [""])[0].strip()
    if px:
        argv += ["--proxy", px]
    targets = (qs.get("targets") or [""])[0].split()
    if not targets:
        raise ValueError("대상을 하나 이상 입력")
    if len(targets) > 8:
        raise ValueError("대상은 최대 8개")
    # '--' 뒤는 대상으로만 해석된다 ('-' 로 시작하는 대상이 옵션으로 읽히지 않게).
    argv += ["--no-color", "--"] + targets
    return argv


class Handler(BaseHTTPRequestHandler):
    server_version = "netcheck-gui"

    def log_message(self, fmt, *args):        # 요청 로그 출력 안 함
        pass

    def _auth(self, qs: dict) -> bool:
        tok = (qs.get("token") or [""])[0]
        # 상수 시간 비교
        return secrets.compare_digest(tok.encode(), TOKEN.encode())

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # 외부 자원을 쓰지 않으므로 CSP 로 차단한다.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'"
                         + (" 'unsafe-eval'" if APP_MODE else "")
                         + "; connect-src 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self) -> None:
        global LAST_SEEN
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if self._auth(qs):
            LAST_SEEN = time.time()
        if u.path == "/ping":
            self._send(204 if self._auth(qs) else 403, b"", "text/plain")
            return
        if u.path == "/":
            if not self._auth(qs):
                self._send(403, "토큰 필요. 터미널에 출력된 주소로 접속.".encode(),
                           "text/plain; charset=utf-8")
                return
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        if u.path == "/stop":
            if not self._auth(qs):
                self._send(403, b"forbidden", "text/plain")
                return
            j = Job.get((qs.get("job") or [""])[0])
            if j:
                j.cancel()
            self._send(200, b'{"ok":true}', "application/json")
            return
        if u.path == "/run":
            if not self._auth(qs):
                self._send(403, b"forbidden", "text/plain")
                return
            self._stream(qs)
            return
        self._send(404, b"not found", "text/plain")

    def _stream(self, qs: dict) -> None:
        try:
            argv = build_argv(qs)
        except ValueError as ex:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.end_headers()
            self._event("line", f"  ✘ {ex}")
            self._event("done", {"rc": 2, "payload": None})
            return
        job = Job(argv)
        job.start()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        # 중지 요청용 작업 id 를 먼저 전달
        self._event("job", {"id": job.id})
        try:
            self._pump(job)
        finally:
            if not job.done:                # 연결 종료 → 진단 중단
                job.cancel("disconnect")

    def _pump(self, job: "Job") -> None:
        while True:
            try:
                kind, val = job.q.get(timeout=1.0)
            except queue.Empty:
                # 유휴 연결 종료 방지용 주석 프레임
                # 쓰기 실패로 연결 종료를 감지한다 (진행이 없는 긴 구간도 유지)
                if not self._raw(b": keepalive\n\n"):
                    return
                continue
            if kind in ("line", "ev"):
                if not self._event(kind, val):
                    return
            else:
                self._event("done", {"rc": job.rc, "payload": job.payload,
                                     "report": job.report, "reason": job.reason})
                return

    def _raw(self, data: bytes) -> bool:
        try:
            self.wfile.write(data)
            self.wfile.flush()
            return True
        except (OSError, ValueError):       # 연결 끊김 (Windows ConnectionAbortedError 포함)
            return False

    def _event(self, name: str, data) -> bool:
        payload = json.dumps(data, ensure_ascii=False)
        return self._raw(f"event: {name}\ndata: {payload}\n\n".encode("utf-8"))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    # Windows 의 SO_REUSEADDR 는 사용 중인 포트에 중복 바인딩을 허용하므로 끈다
    allow_reuse_address = os.name != "nt"

    def server_bind(self) -> None:
        # HTTPServer.server_bind 는 getfqdn() 으로 역방향 DNS 를 조회해 환경에 따라
        # 수십 초 멈춘다. 이름은 쓰지 않으므로 조회를 생략한다.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]


def make_server(port: int) -> tuple[ThreadingHTTPServer, str]:
    """127.0.0.1 서버와 접속 URL. port 0 이면 빈 포트를 자동 선택한다."""
    srv = Server(("127.0.0.1", port), Handler)
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/?token={TOKEN}"


def busy() -> bool:
    """실행 중인 진단이 있는지 여부."""
    with Job._lock:
        return any(not j.done for j in Job._jobs.values())


def cancel_all() -> None:
    """실행 중인 진단 중단 (창 종료 시)."""
    with Job._lock:
        for job in Job._jobs.values():
            job.cancel("shutdown")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="netcheck GUI — 브라우저 화면용 로컬 서버")
    ap.add_argument("--port", type=int, default=8787, help="포트 (기본 8787)")
    ap.add_argument("--no-open", action="store_true", help="브라우저 자동 실행 안 함")
    a = ap.parse_args()

    try:
        srv, url = make_server(a.port)
    except OSError as ex:
        print(f"포트 {a.port} 사용 불가: {ex}", file=sys.stderr)
        print("  --port 로 다른 포트 지정 가능.", file=sys.stderr)
        return 1
    # 파이프 출력에서도 주소가 바로 보이도록 flush
    print(f"netcheck GUI  →  {url}", flush=True)
    print("  이 기기에서만 접속 가능. 토큰 없는 요청은 거부.", flush=True)
    print("  종료: Ctrl+C", flush=True)
    if not a.no_open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n종료")
    finally:
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
