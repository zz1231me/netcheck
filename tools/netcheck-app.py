#!/usr/bin/env python3
# netcheck 데스크톱 앱 — GUI 를 네이티브 창으로 실행
#
#   python3 tools/netcheck-app.py              # 창 실행 (pywebview 미설치 시 브라우저)
#   python3 tools/netcheck-app.py --browser    # 브라우저로 실행
#   python3 tools/build-app.py                 # 실행 파일 생성 (PyInstaller)
#
# 창 엔진은 OS 내장 웹뷰를 쓴다: Windows WebView2 · macOS WKWebView · Linux WebKitGTK/Qt.
# 화면과 진단은 netcheck-gui.py · netcheck.py 를 그대로 사용한다 (127.0.0.1 서버 + 토큰).

from __future__ import annotations

import argparse
import importlib.util
import os
import sys
import threading
import time
import webbrowser

TITLE = "netcheck — 계층별 도달성 진단"


def base_dir() -> str:
    """스크립트 위치. PyInstaller 실행 파일이면 압축 해제 경로."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def fix_streams() -> None:
    # 창 모드 실행 파일(Windows --windowed 등)은 stdout/stderr 가 None 이다.
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))


def load_gui():
    path = os.path.join(base_dir(), "netcheck-gui.py")
    spec = importlib.util.spec_from_file_location("netcheck_gui", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["netcheck_gui"] = mod
    spec.loader.exec_module(mod)
    return mod


class Api:
    """창 안 페이지에서 `window.pywebview.api.*` 로 호출하는 함수."""

    def __init__(self) -> None:
        self._window = None          # '_' 로 시작하는 속성은 JS 에 노출되지 않는다

    def save_file(self, name: str, text: str) -> str:
        """저장 대화상자로 파일 저장. 취소하면 빈 문자열."""
        import webview
        r = self._window.create_file_dialog(webview.FileDialog.SAVE, save_filename=name)
        if not r:
            return ""
        path = r if isinstance(r, str) else r[0]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return path


def run_window(url: str) -> bool:
    """네이티브 창 실행. 창이 닫히면 True, 창을 띄울 수 없으면 False."""
    try:
        import webview
    except ImportError:
        print("pywebview 미설치 — 브라우저로 실행 (설치: pip install pywebview)", file=sys.stderr)
        return False
    try:
        api = Api()
        win = webview.create_window(TITLE, url, js_api=api, width=1200, height=880,
                                    min_size=(760, 560), text_select=True)
        api._window = win
        # Windows: WebView2(Edge) 엔진만 사용. 없으면 예외 → 브라우저로 실행
        webview.start(gui="edgechromium" if sys.platform == "win32" else None)
        return True
    except Exception as ex:
        print(f"창 실행 실패 — 브라우저로 실행 ({type(ex).__name__}: {ex})", file=sys.stderr)
        return False


IDLE_EXIT = 300      # 페이지 응답이 이 시간(초) 동안 없으면 종료 (탭 종료 판단)


def run_browser(gui, url: str) -> None:
    print(f"netcheck GUI  →  {url}", flush=True)
    print(f"  종료: Ctrl+C 또는 탭 닫기 ({IDLE_EXIT}초 후 자동 종료)", flush=True)
    webbrowser.open(url)
    started = time.time()
    try:
        while True:
            time.sleep(5)
            seen = gui.LAST_SEEN
            if gui.busy():
                continue        # 진단 중에는 종료하지 않음
            if seen and time.time() - seen > IDLE_EXIT:
                break
            if not seen and time.time() - started > IDLE_EXIT:
                break       # 브라우저가 열리지 않음
    except KeyboardInterrupt:
        pass


# OS 별 pywebview 창 백엔드 모듈
WEBVIEW_BACKEND = {"win32": "webview.platforms.winforms", "darwin": "webview.platforms.cocoa"}


def selftest() -> int:
    """실행 파일에 엔진·화면·창 백엔드·표준 모듈이 모두 포함됐는지 확인한다.

    어떤 실패도 예외로 빠져나가지 않게 한다 (창 모드 실행 파일은 예외 시 대화상자를 띄워 멈춤)."""
    import urllib.request
    srv = None
    try:
        gui = load_gui()
        srv, url = gui.make_server(0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        with urllib.request.urlopen(url, timeout=10) as r:
            if not (r.status == 200 and b'id="verdict"' in r.read()):
                raise RuntimeError("페이지 응답 이상")
        gui.NC.normalize_host("example.com")
        for mod in ("tempfile", "ctypes", "webview",
                    WEBVIEW_BACKEND.get(sys.platform, "webview.platforms.gtk")):
            importlib.import_module(mod)
    except BaseException as ex:            # noqa: B036 — SystemExit 포함 전부 실패로 처리
        print(f"selftest 실패: {type(ex).__name__}: {ex}", file=sys.stderr)
        return 1
    finally:
        if srv is not None:
            srv.shutdown()
    print("selftest ok")
    return 0


def main() -> int:
    fix_streams()
    ap = argparse.ArgumentParser(description="netcheck 데스크톱 앱")
    ap.add_argument("--browser", action="store_true", help="네이티브 창 대신 브라우저로 실행")
    ap.add_argument("--port", type=int, default=0, help="서버 포트 (기본: 빈 포트 자동 선택)")
    ap.add_argument("--selftest", action="store_true",
                    help="엔진·화면 로드와 서버 응답만 확인하고 종료 (빌드 검증용)")
    a, _ = ap.parse_known_args()      # macOS 가 붙이는 -psn_* 인자 무시

    if a.selftest:
        return selftest()
    gui = load_gui()
    gui.APP_MODE = not a.browser
    try:
        srv, url = gui.make_server(a.port)
    except OSError as ex:
        print(f"포트 {a.port} 사용 불가: {ex}", file=sys.stderr)
        return 1
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"netcheck 서버 → {url}", file=sys.stderr, flush=True)
    try:
        if a.browser or not run_window(url):
            gui.APP_MODE = False
            run_browser(gui, url)
    finally:
        gui.cancel_all()
        # 진단이 외부 명령을 종료하고 빠져나올 시간을 짧게 준다
        for _ in range(20):
            if not gui.busy():
                break
            time.sleep(0.1)
        srv.shutdown()
    # 진단 스레드·외부 명령이 남아 있어도 프로세스를 즉시 종료 (창 닫은 뒤 대기 방지)
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
