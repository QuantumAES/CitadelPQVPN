//! Windows version-ресурс (VERSIONINFO) для `citadel-svc.exe` — вкладка «Подробно» в свойствах файла,
//! как у `app.exe` (см. `app/windows/runner/Runner.rc`): версия сборки, название/версия продукта,
//! copyright. Версия берётся из env `CITADEL_VERSION` (build-windows.ps1 прокидывает `-Version`,
//! напр. `0.5.0-pre10`); нет env → версия крейта. Иконка — та же, что у app.exe (app_icons/Windows).
//!
//! Работает только при сборке ПОД Windows (`CARGO_CFG_TARGET_OS == "windows"`): MSVC-таргет использует
//! `rc.exe`, gnu — `windres`. Если компилятора ресурсов нет (кросс-чек с Linux без mingw-tools) —
//! предупреждаем и НЕ валим сборку (бинарь соберётся без ресурса).

fn main() {
    println!("cargo:rerun-if-env-changed=CITADEL_VERSION");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return; // ресурс имеет смысл только для .exe под Windows
    }

    let version = std::env::var("CITADEL_VERSION")
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
    let (a, b, c, d) = numeric_version(&version);
    let packed = ((a as u64) << 48) | ((b as u64) << 32) | ((c as u64) << 16) | (d as u64);

    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "CitadelPQVPN")
        .set("FileDescription", "CitadelPQVPN - postquantum VPN service")
        .set("CompanyName", "CitadelPQVPN")
        .set("LegalCopyright", "Copyright (C) 2026 CitadelPQVPN. All rights reserved.")
        .set("ProductVersion", &version)
        .set("FileVersion", &version)
        .set("InternalName", "citadel-svc")
        .set("OriginalFilename", "citadel-svc.exe");
    res.set_version_info(winresource::VersionInfo::FILEVERSION, packed);
    res.set_version_info(winresource::VersionInfo::PRODUCTVERSION, packed);

    // Брендовая иконка (та же, что у app.exe) — если файл на месте.
    let ico = concat!(env!("CARGO_MANIFEST_DIR"), "/../../app_icons/Windows/app.ico");
    if std::path::Path::new(ico).exists() {
        res.set_icon(ico);
    }

    if let Err(e) = res.compile() {
        println!("cargo:warning=citadel-svc: version-ресурс не встроен ({e}) — нет rc.exe/windres?");
    }
}

/// "a.b.c[-preN|+N]" → числовой FILEVERSION (a,b,c,d): major.minor.patch + build из хвостовых цифр
/// суффикса (`0.5.0-pre10` → 0,5,0,10). Windows FILEVERSION требует 4 числа; строковые поля
/// (FileVersion/ProductVersion) несут полную строку как есть.
fn numeric_version(v: &str) -> (u16, u16, u16, u16) {
    let core = v.split(['-', '+']).next().unwrap_or(v);
    let mut p = core.split('.').map(|x| x.parse::<u16>().unwrap_or(0));
    let (a, b, c) = (p.next().unwrap_or(0), p.next().unwrap_or(0), p.next().unwrap_or(0));
    let d = v
        .split_once('-')
        .or_else(|| v.split_once('+'))
        .map(|(_, suffix)| {
            let trailing: String =
                suffix.chars().rev().take_while(|ch| ch.is_ascii_digit()).collect();
            trailing.chars().rev().collect::<String>().parse().unwrap_or(0)
        })
        .unwrap_or(0);
    (a, b, c, d)
}
