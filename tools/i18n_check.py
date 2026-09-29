#!/usr/bin/env python3
"""Проверка переводов: у каждого t("…") в коде должен быть английский вариант в stand/locale/en/*.json,
и один и тот же ключ в разных файлах не должен переводиться по-разному (иначе побеждает последний файл).

    python tools/i18n_check.py            # строки без перевода и разнобой в дублях; код выхода 1, если есть
    python tools/i18n_check.py --unused   # ещё и переводы, которых в коде больше нет

Строки, которые попадают в t() через переменную (подписи колонок, диагнозы пробника, демо-локации),
перечислены в stand/locale/dynamic.txt по одной на строку: они проверяются на наличие перевода
и не считаются лишними.
"""
import ast
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from stand.i18n import LOCALE_DIR, load_table  # noqa: E402

SOURCES = ["app.py", "run_check.py", "stand"]
DYNAMIC_PATH = os.path.join(LOCALE_DIR, "dynamic.txt")


def dynamic_keys(path=DYNAMIC_PATH):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def python_files():
    for item in SOURCES:
        path = os.path.join(ROOT, item)
        if os.path.isfile(path):
            yield path
            continue
        for folder, _dirs, files in os.walk(path):
            yield from (os.path.join(folder, f) for f in files if f.endswith(".py"))


def keys_in(path):
    """Строки-литералы, переданные в t(). t(переменная) не ловится - такие места переводить явно."""
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), path)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "t"
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            yield node.args[0].value, node.lineno


def conflicts(lang="en"):
    """Ключи, которые встречаются в нескольких файлах перевода с разным переводом."""
    seen = {}
    for path in sorted(glob.glob(os.path.join(LOCALE_DIR, lang, "*.json"))):
        with open(path, encoding="utf-8") as handle:
            for key, value in json.load(handle).items():
                seen.setdefault(key, []).append((os.path.basename(path), value))
    return {key: places for key, places in seen.items() if len({value for _name, value in places}) > 1}


def main():
    table = load_table("en")
    used, missing = set(), []
    for path in python_files():
        for key, line in keys_in(path):
            used.add(key)
            if key not in table:
                missing.append("%s:%d  %s" % (os.path.relpath(path, ROOT), line, key[:100].replace("\n", "\\n")))
    for key in dynamic_keys():
        used.add(key)
        if key not in table:
            missing.append("%s  %s" % (os.path.relpath(DYNAMIC_PATH, ROOT), key[:100]))
    for row in missing:
        print("missing:", row)
    if "--unused" in sys.argv:
        for key in sorted(set(table) - used):
            print("unused:", key[:100].replace("\n", "\\n"))
    clashes = conflicts()
    for key, places in sorted(clashes.items()):
        print("conflicting:", key[:100].replace("\n", "\\n"),
              "; ".join("%s: %s" % (name, value[:60]) for name, value in places))
    print("strings in code: %d, translated: %d, missing: %d, conflicting translations: %d"
          % (len(used), len(used & set(table)), len(missing), len(clashes)))
    return 1 if missing or clashes else 0


if __name__ == "__main__":
    sys.exit(main())
