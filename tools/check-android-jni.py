#!/usr/bin/env python3
"""Сверить имена JNI-символов в Rust с пакетом Kotlin-сервиса (Android).

Зачем отдельная проверка. Имя экспортируемой функции JNI кодирует ПОЛНОЕ имя класса:
`external fun nativeRegister()` в `com.quantumaes.citadelpqvpn.CitadelVpnService` ищется в .so
как `Java_com_quantumaes_citadelpqvpn_CitadelVpnService_nativeRegister`. Связывание
происходит В РАНТАЙМЕ, поэтому расхождение НЕ ломает ни сборку Rust, ни gradle, ни APK:
приложение соберётся, установится, запустится — и упадёт с `UnsatisfiedLinkError` в момент
старта VpnService. На практике это выглядит как «туннель поднялся, а интернета нет»
(не зарегистрировался socket-протектор → исходящий сокет заворачивается в собственный TUN),
и ищется такое долго.

Ровно этот риск возникает при любом переименовании пакета приложения. Проверка стоит
миллисекунды и держит инвариант: пакет в build.gradle.kts == package в .kt == префикс
Java_… в Rust, и у каждого `external fun` есть символ.

Запуск:  python3 tools/check-android-jni.py     (0 — сходится, 1 — расхождение)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GRADLE = REPO / "app" / "android" / "app" / "build.gradle.kts"
KOTLIN_ROOT = REPO / "app" / "android" / "app" / "src" / "main" / "kotlin"
RUST = REPO / "app" / "rust" / "src" / "android_jni.rs"

problems: list[str] = []


def mangle(package: str, cls: str, method: str) -> str:
    """Имя JNI-символа. Подчёркивание в идентификаторе кодируется как `_1` (JNI-мангling)."""
    parts = [p.replace("_", "_1") for p in (*package.split("."), cls, method)]
    return "Java_" + "_".join(parts)


def gradle_value(key: str) -> str | None:
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]+)"', GRADLE.read_text(), re.M)
    return m.group(1) if m else None


def main() -> int:
    for f in (GRADLE, RUST):
        if not f.is_file():
            print(f"нет файла {f.relative_to(REPO)}", file=sys.stderr)
            return 1

    namespace = gradle_value("namespace")
    app_id = gradle_value("applicationId")
    if not namespace:
        problems.append("в build.gradle.kts не нашёл namespace")
    # namespace задаёт пространство имён R/BuildConfig и разрешение относительных ".MainActivity"
    # в манифесте; applicationId — идентификатор в системе. Разойтись они могут осознанно, но у
    # нас это всегда опечатка, поэтому сверяем.
    if namespace and app_id and namespace != app_id:
        problems.append(f"namespace ({namespace}) != applicationId ({app_id}) в build.gradle.kts")

    rust_src = RUST.read_text()
    rust_symbols = set(re.findall(r"\bfn\s+(Java_\w+)", rust_src))
    if not rust_symbols:
        problems.append(f"в {RUST.relative_to(REPO)} нет ни одной функции Java_… — JNI-мост исчез?")

    used: set[str] = set()
    for kt in sorted(KOTLIN_ROOT.rglob("*.kt")):
        text = kt.read_text()
        pkg_m = re.search(r"^package\s+([\w.]+)", text, re.M)
        if not pkg_m:
            continue
        pkg = pkg_m.group(1)

        # Каталог обязан повторять пакет — иначе Kotlin соберётся, но файл легко «потерять».
        expected_dir = KOTLIN_ROOT.joinpath(*pkg.split("."))
        if kt.parent != expected_dir:
            problems.append(
                f"{kt.relative_to(REPO)}: package {pkg} не совпадает с каталогом "
                f"(ожидался {expected_dir.relative_to(REPO)})"
            )
        if namespace and pkg != namespace:
            problems.append(f"{kt.relative_to(REPO)}: package {pkg} != namespace {namespace}")

        for method in re.findall(r"\bexternal\s+fun\s+(\w+)\s*\(", text):
            sym = mangle(pkg, kt.stem, method)
            used.add(sym)
            if sym not in rust_symbols:
                problems.append(
                    f"{kt.relative_to(REPO)}: external fun {method}() ждёт символ {sym}, "
                    f"а в {RUST.relative_to(REPO)} его нет "
                    "(UnsatisfiedLinkError в рантайме, сборка при этом пройдёт)"
                )

    for sym in sorted(rust_symbols - used):
        problems.append(f"{RUST.relative_to(REPO)}: символ {sym} не соответствует ни одному external fun")

    if problems:
        print("JNI-мост НЕ сходится:", file=sys.stderr)
        for p in problems:
            print("  •", p, file=sys.stderr)
        return 1

    print(f"JNI-мост сходится: пакет {namespace}, символов — {len(used)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
