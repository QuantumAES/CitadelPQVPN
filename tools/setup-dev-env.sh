#!/usr/bin/env bash
# =============================================================================
# CitadelPQVPN — установщик окружения для разработки и тестирования
# -----------------------------------------------------------------------------
# Цель: воспроизводимо поднять на чистой Debian/Parrot-машине весь тулчейн под
#   - ядро/сервер (Rust workspace, aws-lc-rs, Docker-демо);
#   - кроссплатформенный клиент (трек C*): Android/Windows/Linux-таргеты,
#     Flutter + flutter_rust_bridge, Android NDK/SDK;
#   - релиз серверного бинаря (musl/arm64, подпись).
#
# Скрипт ИДЕМПОТЕНТЕН: повторный запуск пропускает уже установленное.
# Запускать ОТ ОБЫЧНОГО пользователя (НЕ под sudo/root) — системные пакеты он
# поставит через sudo сам, а rustup/flutter/cargo/venv положит в ваш $HOME.
#
# Использование:
#   tools/setup-dev-env.sh [--core] [--cross] [--android] [--flutter] [--all] [--check]
#
#   --core      (по умолчанию) системные deps + rustup + нативная сборка +
#               cargo-инструменты + python-venv. Достаточно для cargo test и docker-демо.
#   --cross     кросс-таргеты: linux-musl (x86_64/aarch64), windows-gnu (mingw).
#   --android   Android SDK cmdline-tools + NDK + android Rust-таргеты + cargo-ndk (многогигабайтно).
#   --flutter   Flutter SDK (stable) + Linux-desktop deps + frb-codegen.
#   --all       всё вышеперечисленное (полный стек клиента).
#   --check     ничего не ставить, только продиагностировать (doctor).
#
# Примечание про macOS: кросс-сборка под macOS из Linux требует osxcross + Apple SDK
# (лицензия Apple) — здесь НЕ автоматизируется. Собирайте на macOS-хосте или CI-раннере.
# =============================================================================
set -euo pipefail

# ---- пинуемые версии (можно переопределить через env перед запуском) ---------
NDK_VERSION="${NDK_VERSION:-27.2.12479018}"        # LTS NDK r27
ANDROID_PLATFORM="${ANDROID_PLATFORM:-android-36}"   # Flutter 3.44 требует SDK 36
ANDROID_BUILD_TOOLS="${ANDROID_BUILD_TOOLS:-36.0.0}"
CMDLINE_TOOLS_BUILD="${CMDLINE_TOOLS_BUILD:-11076708}"  # commandlinetools-linux-<build>_latest.zip
FLUTTER_CHANNEL="${FLUTTER_CHANNEL:-stable}"
RUST_NIGHTLY="${RUST_NIGHTLY:-nightly}"            # для cargo-fuzz (M6 future)

# ---- пути установки ----------------------------------------------------------
ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
FLUTTER_HOME="${FLUTTER_HOME:-$HOME/flutter}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
BASHRC_MARK_BEGIN="# >>> citadel dev env >>>"
BASHRC_MARK_END="# <<< citadel dev env <<<"

# ---- вывод -------------------------------------------------------------------
c_blue=$'\033[1;34m'; c_grn=$'\033[1;32m'; c_yel=$'\033[1;33m'; c_red=$'\033[1;31m'; c_off=$'\033[0m'
log()  { printf "%s==>%s %s\n"  "$c_blue" "$c_off" "$*"; }
ok()   { printf "%s ok %s %s\n" "$c_grn"  "$c_off" "$*"; }
warn() { printf "%s warn%s %s\n" "$c_yel" "$c_off" "$*" >&2; }
die()  { printf "%serr %s %s\n" "$c_red"  "$c_off" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- sudo / root guard -------------------------------------------------------
if [[ "${EUID}" -eq 0 ]]; then
  die "запущено под root. Запусти от своего пользователя — apt вызовется через sudo сам, а тулчейн ляжет в твой \$HOME."
fi
SUDO=""
if have sudo; then SUDO="sudo"; else warn "sudo не найден — системные пакеты придётся ставить вручную"; fi

apt_install() {
  local missing=()
  for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  if [[ ${#missing[@]} -eq 0 ]]; then ok "apt: уже стоят: $*"; return; fi
  log "apt install: ${missing[*]}"
  $SUDO apt-get update -qq
  $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"
}

# идемпотентно дописать строку в ~/.bashrc внутри маркер-блока
bashrc_add() {
  local line="$1" rc="$HOME/.bashrc"
  touch "$rc"
  grep -qF "$BASHRC_MARK_BEGIN" "$rc" || printf '\n%s\n%s\n' "$BASHRC_MARK_BEGIN" "$BASHRC_MARK_END" >> "$rc"
  grep -qF "$line" "$rc" || sed -i "/$BASHRC_MARK_END/i $line" "$rc"
}

# =============================================================================
# Компоненты
# =============================================================================

install_system_deps() {
  log "Системные пакеты (build deps для aws-lc-rs + утилиты)"
  apt_install build-essential cmake clang lld ninja-build pkg-config perl \
              ca-certificates curl git unzip xz-utils \
              jq zstd minisign python3-venv
  ok "системные deps готовы"
}

install_rust() {
  log "Rust toolchain (rustup)"
  if have rustup; then
    ok "rustup уже стоит: $(rustup --version 2>/dev/null | head -1)"
  else
    warn "сейчас активен системный rustc $(rustc --version 2>/dev/null | awk '{print $2}') без rustup — ставлю rustup в \$HOME (он будет иметь приоритет в PATH)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --default-toolchain stable --profile default
  fi
  # shellcheck disable=SC1090,SC1091
  source "$HOME/.cargo/env"
  bashrc_add 'export PATH="$HOME/.cargo/bin:$PATH"'

  rustup component add clippy rustfmt rust-src 2>/dev/null || true
  log "ставлю nightly (для cargo-fuzz, M6 future)"
  rustup toolchain install "$RUST_NIGHTLY" --profile minimal --component rust-src 2>/dev/null || warn "nightly не поставился — fuzzing отложится"
  ok "rust: $(rustc --version)"
}

install_cargo_tools() {
  log "Cargo-инструменты (FFI/кросс/тесты)"
  # shellcheck disable=SC1090,SC1091
  source "$HOME/.cargo/env"
  local tools=(cargo-ndk flutter_rust_bridge_codegen cargo-nextest)
  for t in "${tools[@]}"; do
    local bin="${t/flutter_rust_bridge_codegen/flutter_rust_bridge_codegen}"
    if have "${bin}"; then ok "$t уже стоит"; else log "cargo install $t"; cargo install --locked "$t"; fi
  done
  # cargo-fuzz — host-инструмент, ставится на stable, запускается на nightly
  have cargo-fuzz && ok "cargo-fuzz уже стоит" || { log "cargo install cargo-fuzz"; cargo install --locked cargo-fuzz || warn "cargo-fuzz не поставился (не критично)"; }
  # UniFFI bindgen (Kotlin/Swift) — опционально
  have uniffi-bindgen && ok "uniffi-bindgen уже стоит" || { log "cargo install uniffi-bindgen"; cargo install --locked uniffi-bindgen || warn "uniffi-bindgen не поставился (нужен на C0.6 для Kotlin/Swift)"; }
  ok "cargo-инструменты готовы"
}

add_cross_targets() {
  log "Кросс-таргеты Rust (musl + windows-gnu)"
  apt_install mingw-w64 musl-tools
  # shellcheck disable=SC1090,SC1091
  source "$HOME/.cargo/env"
  rustup target add \
    x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
    x86_64-pc-windows-gnu
  ok "кросс-таргеты добавлены (linux-musl x2, windows-gnu)"
  warn "Windows ARM64 и macOS из Linux не кроссятся штатно — собирать на нативном хосте/CI-раннере"
}

install_android() {
  log "Android SDK cmdline-tools + NDK $NDK_VERSION (многогигабайтно)"
  apt_install openjdk-17-jdk-headless
  mkdir -p "$ANDROID_HOME"
  local cli="$ANDROID_HOME/cmdline-tools/latest"
  if [[ ! -x "$cli/bin/sdkmanager" ]]; then
    local zip="/tmp/cmdline-tools.zip"
    log "качаю commandlinetools build $CMDLINE_TOOLS_BUILD"
    curl -fsSL "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_BUILD}_latest.zip" -o "$zip"
    rm -rf "$ANDROID_HOME/cmdline-tools/tmp"; mkdir -p "$ANDROID_HOME/cmdline-tools/tmp"
    unzip -q "$zip" -d "$ANDROID_HOME/cmdline-tools/tmp"
    rm -rf "$cli"; mkdir -p "$(dirname "$cli")"
    mv "$ANDROID_HOME/cmdline-tools/tmp/cmdline-tools" "$cli"
    rm -rf "$ANDROID_HOME/cmdline-tools/tmp" "$zip"
  else ok "cmdline-tools уже есть"; fi

  export ANDROID_HOME
  local sm="$cli/bin/sdkmanager"
  log "принимаю лицензии и ставлю platform-tools / $ANDROID_PLATFORM / build-tools $ANDROID_BUILD_TOOLS / NDK $NDK_VERSION"
  yes 2>/dev/null | "$sm" --sdk_root="$ANDROID_HOME" --licenses >/dev/null || true
  "$sm" --sdk_root="$ANDROID_HOME" \
    "platform-tools" "platforms;$ANDROID_PLATFORM" \
    "build-tools;$ANDROID_BUILD_TOOLS" "ndk;$NDK_VERSION" >/dev/null

  bashrc_add "export ANDROID_HOME=\"$ANDROID_HOME\""
  bashrc_add "export ANDROID_NDK_HOME=\"$ANDROID_HOME/ndk/$NDK_VERSION\""
  bashrc_add 'export PATH="$ANDROID_HOME/platform-tools:$PATH"'

  # shellcheck disable=SC1090,SC1091
  source "$HOME/.cargo/env"
  log "android Rust-таргеты"
  rustup target add aarch64-linux-android armv7-linux-androideabi \
                    x86_64-linux-android i686-linux-android
  ok "Android-стек готов (R1 проверяется сборкой на C0.6: cargo ndk -t arm64-v8a build)"
  warn "если aws-lc-rs под NDK потребует Go — поставь golang-go (FIPS-ветка); обычная сборка обходится cmake+clang"
}

install_flutter() {
  log "Flutter SDK ($FLUTTER_CHANNEL) + Linux-desktop deps"
  apt_install clang cmake ninja-build pkg-config libgtk-3-dev liblzma-dev libstdc++-12-dev
  if [[ -x "$FLUTTER_HOME/bin/flutter" ]]; then
    ok "Flutter уже клонирован в $FLUTTER_HOME"
  else
    log "git clone flutter ($FLUTTER_CHANNEL) → $FLUTTER_HOME"
    git clone --depth 1 -b "$FLUTTER_CHANNEL" https://github.com/flutter/flutter.git "$FLUTTER_HOME"
  fi
  bashrc_add "export PATH=\"$FLUTTER_HOME/bin:\$PATH\""
  export PATH="$FLUTTER_HOME/bin:$PATH"
  log "flutter precache + enable-linux-desktop (первый запуск тянет Dart SDK)"
  flutter config --enable-linux-desktop --no-analytics >/dev/null 2>&1 || true
  flutter precache --linux --android >/dev/null 2>&1 || warn "precache частично — доустановит при первой сборке"
  ok "Flutter готов (проверь: flutter doctor)"
}

setup_python() {
  log "Python venv (эталон obfs + cmake для aws-lc)"
  [[ -d "$VENV_DIR" ]] || python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install -q --upgrade pip
  "$VENV_DIR/bin/pip" install -q -r "$REPO_DIR/tools/requirements.txt"
  "$VENV_DIR/bin/python" -c "import blake3, cryptography; print('blake3', blake3.__version__)" \
    && ok "python-эталон готов (.venv)" || die "venv не собрался"
}

# =============================================================================
# Диагностика
# =============================================================================
doctor() {
  log "Диагностика окружения"
  # shellcheck disable=SC1090,SC1091
  [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
  [[ -d "$FLUTTER_HOME/bin" ]] && export PATH="$FLUTTER_HOME/bin:$PATH"

  printf '  rustc      : %s\n' "$(rustc --version 2>/dev/null || echo НЕТ)"
  printf '  cargo      : %s (%s)\n' "$(cargo --version 2>/dev/null | awk '{print $2}' || echo НЕТ)" "$(command -v cargo)"
  printf '  targets    : %s\n' "$(rustup target list --installed 2>/dev/null | tr '\n' ' ' || echo '— (нет rustup)')"
  for t in cargo-ndk flutter_rust_bridge_codegen cargo-nextest cargo-fuzz uniffi-bindgen; do
    printf '  %-10s : %s\n' "$t" "$(have "$t" && echo есть || echo НЕТ)"
  done
  printf '  cmake/clang: %s / %s\n' "$(have cmake && echo есть || echo НЕТ)" "$(have clang && echo есть || echo НЕТ)"
  printf '  mingw      : %s\n' "$(have x86_64-w64-mingw32-gcc && echo есть || echo НЕТ)"
  printf '  docker     : %s\n' "$(docker --version 2>/dev/null || echo НЕТ)"
  printf '  android    : NDK=%s\n' "${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION (если ставился)}"
  printf '  flutter    : %s\n' "$(flutter --version 2>/dev/null | head -1 || echo НЕТ)"
  printf '  venv       : %s\n' "$([[ -x "$VENV_DIR/bin/python" ]] && "$VENV_DIR/bin/python" -c 'import blake3,cryptography;print("ok")' 2>/dev/null || echo НЕТ)"
  echo
  if have flutter; then log "flutter doctor:"; flutter doctor 2>/dev/null || true; fi
  warn "Открой новый shell или: source ~/.bashrc — чтобы подхватились PATH (cargo/flutter/android)"
}

# =============================================================================
# Точка входа
# =============================================================================
DO_CORE=0 DO_CROSS=0 DO_ANDROID=0 DO_FLUTTER=0 DO_CHECK=0
[[ $# -eq 0 ]] && DO_CORE=1
for arg in "$@"; do
  case "$arg" in
    --core)    DO_CORE=1 ;;
    --cross)   DO_CROSS=1 ;;
    --android) DO_ANDROID=1 ;;
    --flutter) DO_FLUTTER=1 ;;
    --all)     DO_CORE=1; DO_CROSS=1; DO_ANDROID=1; DO_FLUTTER=1 ;;
    --check)   DO_CHECK=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) die "неизвестный флаг: $arg (см. --help)" ;;
  esac
done

if [[ "$DO_CHECK" -eq 1 ]]; then doctor; exit 0; fi

log "CitadelPQVPN dev-env · repo: $REPO_DIR"
if [[ "$DO_CORE" -eq 1 ]]; then
  install_system_deps
  install_rust
  install_cargo_tools
  setup_python
fi
[[ "$DO_CROSS"   -eq 1 ]] && add_cross_targets
[[ "$DO_ANDROID" -eq 1 ]] && install_android
[[ "$DO_FLUTTER" -eq 1 ]] && install_flutter

echo
doctor
echo
ok "Готово. Дальше:"
echo "    source ~/.bashrc                 # подхватить PATH"
echo "    cargo test                       # 49 тестов ядра"
echo "    bash docker/run-demo.sh          # 15 тестов реального туннеля"
[[ "$DO_CORE" -eq 1 && "$DO_ANDROID" -eq 0 ]] && \
  echo "    ./tools/setup-dev-env.sh --all   # полный стек клиента (Android+Flutter+кросс)"
