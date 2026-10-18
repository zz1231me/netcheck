#!/usr/bin/env python3
# netcheck 데스크톱 앱 빌드 (PyInstaller)
#
#   pip install -r tools/requirements-app.txt
#   python3 tools/build-app.py
#
# 결과물 (빌드한 OS 용만 생성됨 — 교차 빌드 불가):
#   macOS    dist/netcheck.app
#   Windows  dist/netcheck.exe
#   Linux    dist/netcheck
#
# netcheck.py · netcheck-gui.py 는 실행 시 파일 경로로 불러오므로 PyInstaller 가
# import 를 추적하지 못한다. 두 파일의 import 를 직접 읽어 hidden import 로 넘긴다.

from __future__ import annotations

import ast
import importlib.util
import os
import platform
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCES = ["netcheck.py", "netcheck-gui.py"]


def imports_of(path: str) -> set[str]:
    tree = ast.parse(open(path, encoding="utf-8").read())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
    return names


def hidden_imports() -> list[str]:
    names: set[str] = set()
    for src in SOURCES:
        names |= imports_of(os.path.join(HERE, src))
    names.discard("__future__")
    # 현재 OS 에 없는 모듈(예: macOS 의 winreg)은 제외
    return sorted(n for n in names if importlib.util.find_spec(n.split(".")[0]))


def main() -> int:
    # Windows CI 등 cp1252 콘솔에서 한글 출력 오류 방지
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        import PyInstaller.__main__ as pyi
    except ImportError:
        print("PyInstaller 미설치 — pip install -r tools/requirements-app.txt", file=sys.stderr)
        return 1
    if importlib.util.find_spec("webview") is None:
        print("pywebview 미설치 — pip install -r tools/requirements-app.txt", file=sys.stderr)
        return 1

    system = platform.system()
    args = [
        os.path.join(HERE, "netcheck-app.py"),
        "--name", "netcheck",
        "--windowed",
        "--noconfirm",
        "--clean",
        "--distpath", os.path.join(ROOT, "dist"),
        "--workpath", os.path.join(ROOT, "build"),
        "--specpath", os.path.join(ROOT, "build"),
    ]
    # macOS 는 .app 번들(onedir), Windows·Linux 는 단일 실행 파일
    if system != "Darwin":
        args.append("--onefile")
    else:
        args += ["--osx-bundle-identifier", "local.netcheck"]
    for src in SOURCES:
        args += ["--add-data", f"{os.path.join(HERE, src)}{os.pathsep}."]
    for mod in hidden_imports():
        args += ["--hidden-import", mod]

    print(f"빌드: {system} {platform.machine()} · Python {platform.python_version()}")
    pyi.run(args)

    out = {"Darwin": "netcheck.app", "Windows": "netcheck.exe"}.get(system, "netcheck")
    path = os.path.join(ROOT, "dist", out)
    if not os.path.exists(path):
        print("빌드 결과물 없음 — 위 PyInstaller 로그 확인", file=sys.stderr)
        return 1
    shutil.rmtree(os.path.join(ROOT, "build"), ignore_errors=True)
    if system == "Darwin":
        # .app 과 함께 생기는 onedir 폴더는 중복이므로 삭제
        shutil.rmtree(os.path.join(ROOT, "dist", "netcheck"), ignore_errors=True)
    print(f"\n완료: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
