"""Правка зашифрованных файлов расписания и целей.

Сайт лежит на GitHub Pages и писать в репозиторий не умеет — значит пункты
заводятся отсюда, а результат уезжает обычным коммитом. Формат один на оба
файла: tasks.json (пункты расписания) и goals.json (цели на месяц и сезон).

    {"v": 2, "kind": "tasks", "salt": "<base64>", "items": ["<base64>", ...]}

Каждый пункт — свой фрагмент со своим вектором. Так новый пункт дописывается
одной строкой, а прежние остаются байт в байт теми же: файл читается в diff'е
и правится без переписывания целиком.

Все фрагменты одной длины, а их число округлено вверх пустышками. Иначе по
файлу видно, сколько у человека дел и насколько они подробные, — время и текст
шифротекст прячет, а вот эти две вещи выдавала бы сама его форма.

Пароль берётся из --password, из SCHEDULE_PASSWORD, из .env рядом с репозиторием
или спрашивается — в таком порядке. Аргумент нужен там, где нет ни .env, ни
возможности выставить переменную окружения. В файлы пароль не пишется.

    python tools/vault.py list tasks.json
    python tools/vault.py list tasks.json --password "..."
    python tools/vault.py list tasks.json --date 2026-09-10
    python tools/vault.py add tasks.json --title "Сдать курсовую" --date 2026-09-10 --time 14:00
    python tools/vault.py edit tasks.json --id <id> --time 16:00
    python tools/vault.py rm tasks.json --id <id>
    python tools/vault.py import tasks.json goals-draft.json
"""

import argparse
import base64
import getpass
import json
import os
import secrets
import sys
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ITERATIONS = 150_000          # столько же, сколько выводит ключ сайт
SLOT = 512                    # длина открытого блока после набивки, байт
BATCH = 16                    # число фрагментов округляется вверх до кратного

CATEGORIES = ("study", "work", "personal", "other")
HORIZONS = ("month", "season")


# ---- формат фрагмента -------------------------------------------------------

def read_password():
    """Переменная окружения, потом .env рядом с репозиторием, потом спросим."""
    if os.environ.get("SCHEDULE_PASSWORD"):
        return os.environ["SCHEDULE_PASSWORD"]
    env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env):
        with open(env, encoding="utf-8") as f:
            for line in f:
                key, _, value = line.partition("=")
                if key.strip() == "SCHEDULE_PASSWORD":
                    return value.strip()
    return getpass.getpass("Пароль: ")


def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def pad(raw):
    """Набивка до одного размера: длина фрагмента иначе выдаёт объём записи."""
    if len(raw) + 2 > SLOT:
        raise SystemExit(f"пункт длиннее {SLOT - 2} байт — сократите заметку")
    return len(raw).to_bytes(2, "big") + raw + b"\0" * (SLOT - 2 - len(raw))


def unpad(block):
    size = int.from_bytes(block[:2], "big")
    return block[2:2 + size]


def seal(key, item):
    raw = pad(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    iv = secrets.token_bytes(12)
    return base64.b64encode(iv + AESGCM(key).encrypt(iv, raw, None)).decode()


def unseal(key, fragment):
    blob = base64.b64decode(fragment)
    raw = unpad(AESGCM(key).decrypt(blob[:12], blob[12:], None))
    return json.loads(raw) if raw else None       # пустышка расшифруется в None


def load(path, password):
    """Читает файл и отдаёт (данные файла, ключ, живые пункты)."""
    if not os.path.exists(path):
        salt = secrets.token_bytes(16)
        kind = "goals" if os.path.basename(path).startswith("goals") else "tasks"
        data = {"v": 2, "kind": kind, "salt": base64.b64encode(salt).decode(), "items": []}
        return data, derive_key(password, salt), []

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    key = derive_key(password, base64.b64decode(data["salt"]))
    items = []
    for fragment in data["items"]:
        try:
            item = unseal(key, fragment)
        except Exception:
            raise SystemExit("файл этим паролем не открывается")
        if item is not None:
            items.append(item)
    return data, key, items


def save(path, data, key, items):
    """Пересобирает items: число фрагментов округляется вверх пустышками."""
    fragments = [seal(key, item) for item in items]
    # Пустой файл выдал бы, что дел нет вовсе, — блок пустышек есть всегда.
    while len(fragments) % BATCH or not fragments:
        fragments.append(seal(key, None))
    data["items"] = fragments
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def save_appending(path, data, key, items, added):
    """Добавление не трогает прежние строки: новые фрагменты идут в хвост.

    Пустышки в хвосте тратятся первыми — пока их хватает, файл прирастает
    ровно одной изменённой строкой на пункт.
    """
    fragments = list(data["items"])
    for item in added:
        spare = next((i for i in range(len(fragments)) if _is_blank(key, fragments[i])), None)
        if spare is None:
            fragments.append(seal(key, item))
        else:
            fragments[spare] = seal(key, item)
    data["items"] = fragments
    while len(data["items"]) % BATCH:
        data["items"].append(seal(key, None))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


def _is_blank(key, fragment):
    try:
        return unseal(key, fragment) is None
    except Exception:
        return False


# ---- пункты -----------------------------------------------------------------

def make_task(args, prev=None):
    prev = prev or {}
    task = {
        "id": prev.get("id") or str(uuid.uuid4()),
        "title": args.title if args.title is not None else prev.get("title", ""),
        "date": args.date if args.date is not None else prev.get("date", ""),
        "time": args.time if args.time is not None else prev.get("time", ""),
        "duration": int(args.duration) if args.duration else prev.get("duration"),
        "category": args.cat if args.cat is not None else prev.get("category", "study"),
        "note": args.note if args.note is not None else prev.get("note", ""),
        "done": prev.get("done", False),
    }
    if not task["title"] or not task["date"]:
        raise SystemExit("у пункта расписания обязательны --title и --date")
    if task["category"] not in CATEGORIES:
        raise SystemExit(f"категория одна из: {', '.join(CATEGORIES)}")
    return task


def make_goal(args, prev=None):
    prev = prev or {}
    goal = {
        "id": prev.get("id") or str(uuid.uuid4()),
        "title": args.title if args.title is not None else prev.get("title", ""),
        "horizon": args.horizon if args.horizon is not None else prev.get("horizon", "month"),
        "period": args.period if args.period is not None else prev.get("period", ""),
        "note": args.note if args.note is not None else prev.get("note", ""),
        "done": prev.get("done", False),
    }
    if not goal["title"]:
        raise SystemExit("у цели обязателен --title")
    if goal["horizon"] not in HORIZONS:
        raise SystemExit(f"горизонт один из: {', '.join(HORIZONS)}")
    return goal


def show(items, kind):
    if not items:
        print("пусто")
        return
    if kind == "goals":
        for goal in sorted(items, key=lambda g: (g.get("horizon", ""), g.get("period", ""))):
            mark = "x" if goal.get("done") else " "
            period = f" · {goal['period']}" if goal.get("period") else ""
            print(f"[{mark}] {goal.get('horizon', '')}{period}  {goal['title']}  ({goal['id'][:8]})")
            if goal.get("note"):
                print(f"      {goal['note']}")
        return
    for task in sorted(items, key=lambda t: (t.get("date", ""), t.get("time", ""))):
        mark = "x" if task.get("done") else " "
        when = task.get("time") or "--:--"
        length = f" +{task['duration']}м" if task.get("duration") else ""
        print(f"[{mark}] {task.get('date', '')} {when}{length}  {task['title']}"
              f"  [{task.get('category', '')}]  ({task['id'][:8]})")
        if task.get("note"):
            print(f"      {task['note']}")


def find(items, ident):
    hits = [i for i in items if i["id"] == ident or i["id"].startswith(ident)]
    if not hits:
        raise SystemExit(f"пункт {ident} не найден")
    if len(hits) > 1:
        raise SystemExit(f"под {ident} подходит несколько пунктов — уточните id")
    return hits[0]


# ---- команды ----------------------------------------------------------------

def main():
    # Консоль Windows по умолчанию не в utf-8, и расшифрованное вышло бы кракозябрами.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("file", help="tasks.json или goals.json")
        p.add_argument("--password", help="если не задан — SCHEDULE_PASSWORD, .env или спросим")

    def fields(p):
        p.add_argument("--title")
        p.add_argument("--date", help="ISO, например 2026-09-10")
        p.add_argument("--time", help="ЧЧ:ММ")
        p.add_argument("--duration", help="минут")
        p.add_argument("--cat", choices=CATEGORIES)
        p.add_argument("--horizon", choices=HORIZONS, help="только для целей")
        p.add_argument("--period", help="только для целей, например «сентябрь 2026»")
        p.add_argument("--note")

    p = sub.add_parser("list", help="расшифровать и показать")
    common(p)
    p.add_argument("--date", help="только за эту дату")

    p = sub.add_parser("add", help="добавить пункт")
    common(p)
    fields(p)

    p = sub.add_parser("edit", help="изменить пункт")
    common(p)
    p.add_argument("--id", required=True)
    p.add_argument("--done", choices=("yes", "no"))
    fields(p)

    p = sub.add_parser("rm", help="удалить пункт")
    common(p)
    p.add_argument("--id", required=True)

    p = sub.add_parser("import", help="залить пачку пунктов из обычного json")
    common(p)
    p.add_argument("source", help="json со списком или {\"tasks\": [...]}")

    args = parser.parse_args()

    password = args.password or read_password()
    data, key, items = load(args.file, password)
    kind = data.get("kind", "tasks")
    build = make_goal if kind == "goals" else make_task

    if args.cmd == "list":
        if getattr(args, "date", None):
            items = [i for i in items if i.get("date") == args.date]
        show(items, kind)
        return

    if args.cmd == "add":
        item = build(args)
        save_appending(args.file, data, key, items, [item])
        print(f"добавлен {item['id'][:8]} — {item['title']}")
        return

    if args.cmd == "edit":
        prev = find(items, args.id)
        item = build(args, prev)
        if args.done:
            item["done"] = args.done == "yes"
        items[items.index(prev)] = item
        save(args.file, data, key, items)
        print(f"изменён {item['id'][:8]} — {item['title']}")
        return

    if args.cmd == "rm":
        item = find(items, args.id)
        items.remove(item)
        save(args.file, data, key, items)
        print(f"удалён {item['id'][:8]} — {item['title']}")
        return

    if args.cmd == "import":
        with open(args.source, encoding="utf-8") as f:
            parsed = json.load(f)
        raw = parsed if isinstance(parsed, list) else parsed.get("tasks") or parsed.get("goals")
        if not isinstance(raw, list):
            raise SystemExit("в исходном файле нет списка пунктов")
        added = []
        for entry in raw:
            stub = argparse.Namespace(**{k: None for k in
                                         ("title", "date", "time", "duration", "cat", "horizon", "period", "note")})
            for src, dst in (("title", "title"), ("date", "date"), ("time", "time"),
                             ("duration", "duration"), ("category", "cat"),
                             ("horizon", "horizon"), ("period", "period"), ("note", "note")):
                if entry.get(src) is not None:
                    setattr(stub, dst, entry[src])
            added.append(build(stub))
        save_appending(args.file, data, key, items, added)
        print(f"залито пунктов: {len(added)}")
        return


if __name__ == "__main__":
    sys.exit(main())
