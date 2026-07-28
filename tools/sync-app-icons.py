#!/usr/bin/env python3
"""Разложить брендовые иконки из `app_icons/` по всем клиентам CitadelPQVPN.

Мастер-набор лежит в `app_icons/<платформа>/` — его готовит дизайн, руками его никто не
раскладывает. Этот инструмент идемпотентен: гоняется после каждой смены арта и приводит
дерево проекта в соответствие с мастером.

Куда что попадает:

  Android   app_icons/Android/res/mipmap-*/ic_launcher.png
              → app/android/app/src/main/res/mipmap-*/ic_launcher.png          (копия)
            + ic_launcher_foreground.png ГЕНЕРИРУЕТСЯ (см. ниже)
            + values/ic_launcher_background.xml — цвет фона под маску
  Windows   app_icons/Windows/app.ico
              → app/windows/runner/resources/app_icon.ico                      (копия)
            (иконку трея Windows-раннер делает в рантайме из этого же IDI_APP_ICON, а
             citadel-winsvc/build.rs читает app.ico напрямую — им ничего не нужно)
  iOS       app_icons/iOS/AppIcon.appiconset/*.png
              → app/ios/Runner/Assets.xcassets/AppIcon.appiconset/             (по Contents.json)
  Linux     ничего копировать не нужно: tools/mk-client-release.sh кладёт в тарбол
            app_icons/Linux/<N>x<N>/apps/app.png напрямую — только проверяем, что набор на месте.

Почему Android-foreground нельзя просто скопировать. На Android 8+ систему интересует НЕ
`ic_launcher.png`, а adaptive-иконка: слой 108dp, из которого маска показывает центральные
72dp (остальное срезается любой формой — круг, squircle, капля). Подменив только легаси-PNG,
получишь на современном телефоне СТАРУЮ иконку и не поймёшь, почему. Поэтому foreground
собирается здесь: арт вписывается ровно в безопасные 72dp по центру прозрачного холста.

Запуск:  python3 tools/sync-app-icons.py [--check]
  --check   ничего не писать, только сказать, что разошлось (для CI)
"""

from __future__ import annotations

import json
import math
import shutil
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    sys.exit("нужен Pillow: pip install Pillow  (или запусти из .venv проекта)")

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "app_icons"
APP = REPO / "app"

CHECK = "--check" in sys.argv[1:]
changed: list[str] = []
problems: list[str] = []


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(REPO))
    except ValueError:
        return str(p)


def put(dst: Path, data: bytes) -> None:
    """Записать файл, если содержимое отличается (иначе не трогаем mtime и git)."""
    if dst.exists() and dst.read_bytes() == data:
        return
    changed.append(rel(dst))
    if CHECK:
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)


def png_bytes(im: Image.Image) -> bytes:
    import io

    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return buf.getvalue()


def resized(src: Image.Image, px: int) -> Image.Image:
    if src.size == (px, px):
        return src
    return src.resize((px, px), Image.LANCZOS)


# ─────────────────────────────── Android ───────────────────────────────

# Плотности Android и сторона холста adaptive-слоя (108dp в пикселях этой плотности).
ANDROID_DENSITIES = {
    "mdpi": 108,
    "hdpi": 162,
    "xhdpi": 216,
    "xxhdpi": 324,
    "xxxhdpi": 432,
}
# Маска adaptive-иконки вырезает из холста 108dp центральные 72dp — но вырезает ФОРМОЙ, и
# круглый лаунчер даёт КРУГ Ø72dp, вписанный в этот квадрат (squircle/капля/скруглённый
# квадрат его содержат, так что круг — худший случай).
#
# Поэтому вписывать арт в КВАДРАТ 72dp нельзя: его углы лежат ВНЕ круга и срезаются. У широкого
# лого (360×188) полудиагональ выходила 40.6dp при радиусе маски 36dp — ровно те «немного
# обрезанные углы» на круглом лаунчере.
#
# Вписываем по ДИАГОНАЛИ рамки арта в safe-круг Google Ø66dp: арт целиком внутри круга маски,
# плюс 3dp запаса до кромки (без запаса лого упирается в неё и выглядит тесно).
SAFE_CIRCLE = 66 / 108


def best_android_master() -> Image.Image | None:
    """Самый крупный арт с прозрачным фоном — из него собирается foreground.

    `playstore-icon.png` не годится: он по требованиям Google непрозрачный, и его белый
    фон стал бы белым квадратом поверх маски.
    """
    for cand in (
        SRC / "Linux" / "512x512" / "apps" / "app.png",
        SRC / "Linux" / "256x256" / "apps" / "app.png",
        SRC / "Android" / "res" / "mipmap-xxxhdpi" / "ic_launcher.png",
    ):
        if cand.exists():
            im = Image.open(cand).convert("RGBA")
            if im.getchannel("A").getextrema()[0] < 255:  # есть прозрачность
                return im
    return None


def android_background_color() -> str | None:
    """Цвет фона под маской = фон непрозрачного мастера (playstore-иконки).

    Смысл — чтобы кромка маски сливалась с артом, а не светилась чужим цветом (ровно из-за
    этого раньше вылезал белый круг на Android 13).
    """
    master = SRC / "Android" / "playstore-icon.png"
    if not master.exists():
        return None
    im = Image.open(master).convert("RGB")
    w, h = im.size
    px = im.load()
    corners = [px[1, 1], px[w - 2, 1], px[1, h - 2], px[w - 2, h - 2]]
    if len(set(corners)) != 1:
        problems.append(
            f"{rel(master)}: углы разного цвета {corners} — цвет фона adaptive-иконки "
            "выбери руками в values/ic_launcher_background.xml"
        )
        return None
    return "#%02X%02X%02X" % corners[0]


def sync_android() -> None:
    res = APP / "android" / "app" / "src" / "main" / "res"
    if not res.is_dir():
        problems.append(f"нет каталога {rel(res)} — Android-клиент не на месте")
        return

    # 1. легаси-PNG (Android 7 и ниже, а также лаунчеры без adaptive)
    for d in ANDROID_DENSITIES:
        s = SRC / "Android" / "res" / f"mipmap-{d}" / "ic_launcher.png"
        if not s.exists():
            problems.append(f"нет {rel(s)}")
            continue
        put(res / f"mipmap-{d}" / "ic_launcher.png", s.read_bytes())

    # 2. adaptive-foreground: арт вписан в safe-круг Ø66dp прозрачного холста 108dp
    master = best_android_master()
    if master is None:
        problems.append("не нашёл прозрачный мастер-арт для adaptive-foreground (app_icons/Linux/512x512)")
    else:
        bbox = master.getbbox()  # обрезаем прозрачные поля мастера — иначе арт выйдет мельче
        art = master.crop(bbox) if bbox else master
        for d, canvas in ANDROID_DENSITIES.items():
            # пропорции сохраняем (арт широкий, квадратный ресайз его раздавит), а масштаб
            # берём из условия «диагональ рамки арта = диаметр safe-круга»
            k = canvas * SAFE_CIRCLE / math.hypot(art.width, art.height)
            w, h = max(1, round(art.width * k)), max(1, round(art.height * k))
            layer = Image.new("RGBA", (canvas, canvas), (0, 0, 0, 0))
            layer.paste(art.resize((w, h), Image.LANCZOS), ((canvas - w) // 2, (canvas - h) // 2))
            put(res / f"mipmap-{d}" / "ic_launcher_foreground.png", png_bytes(layer))

    # 3. цвет фона под маской
    color = android_background_color()
    if color:
        xml = res / "values" / "ic_launcher_background.xml"
        body = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            "<!-- Фон adaptive-иконки: цвет фона мастер-арта (app_icons/Android/playstore-icon.png).\n"
            "     Кромка маски обязана сливаться с картинкой — иначе вокруг иконки светится чужой\n"
            "     цвет (так когда-то вылез белый круг legacy-обработки).\n"
            "     Файл генерируется: tools/sync-app-icons.py -->\n"
            "<resources>\n"
            f'    <color name="ic_launcher_background">{color}</color>\n'
            "</resources>\n"
        )
        put(xml, body.encode())


# ─────────────────────────────── Windows ───────────────────────────────


def sync_windows() -> None:
    s = SRC / "Windows" / "app.ico"
    if not s.exists():
        problems.append(f"нет {rel(s)}")
        return
    put(APP / "windows" / "runner" / "resources" / "app_icon.ico", s.read_bytes())


# ─────────────────────────── Apple (iOS/macOS) ───────────────────────────


def sync_appiconset(kind: str, src_dir: Path, dst_dir: Path) -> None:
    """Разложить набор по `Contents.json`: он — источник истины об именах и размерах.

    Подбор идёт ПО ПИКСЕЛЬНОМУ размеру (size × scale), а не по именам: у Apple одна и та же
    сторона встречается под разными идиомами, а имена в мастере и в проекте не совпадают.
    Точного размера нет — уменьшаем из самого крупного мастера.
    """
    contents = dst_dir / "Contents.json"
    if not contents.is_file():
        problems.append(f"нет {rel(contents)} — набор {kind} пропущен")
        return
    if not src_dir.is_dir():
        problems.append(f"нет мастер-набора {rel(src_dir)} — {kind} НЕ обновлён")
        return

    by_px: dict[int, Image.Image] = {}
    for p in sorted(src_dir.glob("*.png")):
        im = Image.open(p).convert("RGBA")
        if im.width == im.height:
            by_px[im.width] = im
    if not by_px:
        problems.append(f"в {rel(src_dir)} нет квадратных PNG — {kind} НЕ обновлён")
        return
    master = by_px[max(by_px)]

    spec = json.loads(contents.read_text())
    for entry in spec.get("images", []):
        name = entry.get("filename")
        if not name:
            continue
        side = float(entry["size"].split("x")[0])
        scale = int(entry.get("scale", "1x").rstrip("x"))
        px = round(side * scale)
        src_im = by_px.get(px)
        if src_im is None:
            src_im = resized(master, px)
        put(dst_dir / name, png_bytes(src_im))


# ─────────────────────────────── Linux ───────────────────────────────


def check_linux() -> None:
    """Linux-иконки не копируются: релизный скрипт читает app_icons/Linux напрямую.

    Проверяем ровно тот набор размеров, который он берёт, — иначе тарбол молча уедет без
    части иконок (`install -Dm644` просто не вызовется, ошибки не будет).
    """
    missing = [
        f"{sz}x{sz}"
        for sz in (16, 24, 32, 48, 64, 128, 256, 512)
        if not (SRC / "Linux" / f"{sz}x{sz}" / "apps" / "app.png").is_file()
    ]
    if missing:
        problems.append("app_icons/Linux — нет размеров: " + ", ".join(missing))


def main() -> int:
    if not SRC.is_dir():
        sys.exit(f"нет каталога {rel(SRC)}")
    sync_android()
    sync_windows()
    sync_appiconset(
        "iOS",
        SRC / "iOS" / "AppIcon.appiconset",
        APP / "ios" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset",
    )
    # macOS: мастер-набора в app_icons нет. Молча брать iOS-иконку нельзя — у macOS другая
    # подача (арт вписан в холст с полями и скруглением, а не во весь квадрат), это решение
    # дизайна, а не ресайз. Появится app_icons/macOS — строка ниже начнёт работать сама.
    if (SRC / "macOS" / "AppIcon.appiconset").is_dir():
        sync_appiconset(
            "macOS",
            SRC / "macOS" / "AppIcon.appiconset",
            APP / "macos" / "Runner" / "Assets.xcassets" / "AppIcon.appiconset",
        )
    check_linux()

    if changed:
        verb = "разошлось" if CHECK else "обновлено"
        print(f"{verb} файлов: {len(changed)}")
        for c in changed:
            print("  ", c)
    else:
        print("иконки уже соответствуют app_icons/ — менять нечего")
    for p in problems:
        print("ВНИМАНИЕ:", p, file=sys.stderr)
    if CHECK and changed:
        return 1
    return 2 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
