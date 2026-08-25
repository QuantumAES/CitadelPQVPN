#!/usr/bin/env python3
"""Найти неэкранированные обратные апострофы в телах НЕЗАКАВЫЧЕННЫХ heredoc'ов shell-скриптов.

Зачем отдельная проверка. Установщик генерирует entrypoint'ы и compose через `cat <<EOF` — heredoc
БЕЗ кавычек вокруг метки, потому что в тело обязаны подставиться значения самого установщика
($PSK, $ISSUER_PORT и т.д.). Но такой heredoc раскрывает и подстановку команд: любой обратный
апостроф в РУССКОМ КОММЕНТАРИИ (`--role all`, `linkh`, `=""`) исполняется установщиком в момент
генерации. Итог заходa 14 на живом сервере:

    install-citadel-server.sh: command substitution: line 871: syntax error near unexpected token `newline'
    install-citadel-server.sh: line 871: linkh: command not found
    install-citadel-server.sh: line 871: --role: command not found

Скрипт при этом НЕ падает (`set -e` подстановку не ловит), в сгенерированный файл вместо текста
попадает пустая строка, а оператор видит поток «command not found» и не понимает, установилось у
него что-нибудь или нет. Правильная запись — экранировать: \\`--role all\\`.

Проверяем только обратные апострофы: осознанная подстановка пишется как `$(…)` (и её в телах
heredoc'ов много — порты, вложенные `cat <<PORTS`), а вот `` ` `` в наших генераторах встречается
исключительно как кавычки-в-комментарии. Если подстановка через `` ` `` всё же нужна — пометь
строку `# heredoc-exec`.

Запуск:  python3 tools/check-shell-heredocs.py     (0 — чисто, 1 — есть неэкранированные)
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TARGETS = sorted((REPO / "tools").glob("*.sh")) + sorted((REPO / "docker").glob("*.sh"))

# `cat <<EOF`, `cat <<-EOF`, `X="$(cat <<EOF`. Закавыченная метка (<<'EOF', <<"EOF") НЕ раскрывает
# ничего — такие heredoc'и пропускаем.
# `<<TAG` / `<<-TAG` / `<<'TAG'`. Отрицательные lookaround отсекают here-string `<<<` и текст
# вида "# <<< citadel dev env <<<" в обычной строке.
OPEN = re.compile(r"(?<!<)<<-?\s*(?P<q>['\"]?)(?P<tag>[A-Za-z_][A-Za-z0-9_]*)(?P=q)(?!<)")
ALLOW = "# heredoc-exec"


def unescaped_backticks(body_line: str) -> int:
    """Сколько обратных апострофов в строке тела heredoc'а НЕ экранировано."""
    n = 0
    i = 0
    while i < len(body_line):
        if body_line[i] == "\\":
            i += 2
            continue
        if body_line[i] == "`":
            n += 1
        i += 1
    return n


def main() -> int:
    problems: list[str] = []
    for path in TARGETS:
        lines = path.read_text(encoding="utf-8").splitlines()
        tag: str | None = None
        start = 0
        for n, line in enumerate(lines, 1):
            if tag is None:
                m = OPEN.search(line)
                if m and not m.group("q"):
                    tag, start = m.group("tag"), n
                continue
            if line.strip() == tag:
                tag = None
                continue
            if ALLOW in line:
                continue
            if unescaped_backticks(line):
                problems.append(
                    f"{path.relative_to(REPO)}:{n}: неэкранированный ` в теле heredoc'а "
                    f"<<{tag} (открыт на строке {start}) — исполнится ПРИ ГЕНЕРАЦИИ:\n      {line.strip()}"
                )
    if problems:
        print("Подстановка команд внутри незакавыченного heredoc'а:\n", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        print(
            "\nЭкранируй: \\`…\\` — либо пометь строку `# heredoc-exec`, если подстановка нужна.",
            file=sys.stderr,
        )
        return 1
    print(f"heredoc'и чисты ({len(TARGETS)} скрипт(ов))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
