"""Правка личного расписания: зашифрованные записи плюс зашифрованный индекс.

Расписание группы приходит из raspisanie-3bi1 и не шифруется — оно публичное.
Личное лежит здесь:

    my-data.json   {"v": 1, "items": ["<base64>", ...]}
    index.json     {"v": 1, "salt": "<base64>", "index": "<base64>"}

Каждая запись — свой фрагмент со своим вектором. Новая встаёт одной строкой,
правка меняет одну строку, соседние остаются байт в байт теми же.

Индекс зашифрован целиком и читается первым: внутри пары «дата — позиция
фрагмента». По нему сайт берёт нужный отрезок и расшифровывает только его,
не трогая остальной файл. Наружу при этом не торчит ни одной даты.

Соль лежит в index.json — он и открывается первым.

Пароль: --password, SCHEDULE_PASSWORD, .env рядом с репозиторием или спросим.

    python tools/vault.py list
    python tools/vault.py list --from 07.09.2026 --to 13.09.2026
    python tools/vault.py add --subject "Курсовая: глава 2" --date 10.09.2026 --pair 3
    python tools/vault.py edit --id 5019e955 --pair 4
    python tools/vault.py rm --id 5019e955
"""

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import sys
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DATA_FILE = "my-data.json"
INDEX_FILE = "index.json"

ITERATIONS = 150_000     # столько же выводит ключ сайт
SLOT = 512               # длина записи после набивки: размер не должен ничего выдавать
BATCH = 16               # число фрагментов округляется вверх до кратного

DATE_RE = re.compile(r"^\d{2}\.\d{2}\.\d{4}$")

# Те же пары, что в расписании группы: номер ставит запись в строку сетки.
PAIRS = {
    "1": "8:30–10:00",
    "2": "10:10–11:40",
    "3": "12:30–14:00",
    "4": "14:10–15:40",
    "5": "15:50–17:20",
    "6": "17:30–19:00",
    "7": "19:10–20:40",
}
TYPES = ("Лекция", "Семинар", "Практика", "Своё")


# ---- пароль и ключ ----------------------------------------------------------

def root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_password(given):
    if given:
        return given
    if os.environ.get("SCHEDULE_PASSWORD"):
        return os.environ["SCHEDULE_PASSWORD"]
    env = os.path.join(root(), ".env")
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


# ---- фрагменты --------------------------------------------------------------

def b64(raw):
    return base64.b64encode(raw).decode()


def unb64(text):
    return base64.b64decode(text)


def seal(key, value):
    """Шифрует запись блоком постоянной длины: длина не должна выдавать объём."""
    raw = b"" if value is None else json.dumps(value, ensure_ascii=False,
                                               separators=(",", ":")).encode("utf-8")
    if len(raw) + 2 > SLOT:
        raise SystemExit(f"запись длиннее {SLOT - 2} байт — сократите заметку")
    block = len(raw).to_bytes(2, "big") + raw + b"\0" * (SLOT - 2 - len(raw))
    iv = secrets.token_bytes(12)
    return b64(iv + AESGCM(key).encrypt(iv, block, None))


def unseal(key, fragment):
    blob = unb64(fragment)
    block = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    size = int.from_bytes(block[:2], "big")
    return json.loads(block[2:2 + size]) if size else None


def seal_index(key, entries):
    """Индекс шифруется одним куском — он маленький и читается первым."""
    raw = json.dumps(entries, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    iv = secrets.token_bytes(12)
    return b64(iv + AESGCM(key).encrypt(iv, raw, None))


def unseal_index(key, blob):
    raw = unb64(blob)
    return json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], None))


# ---- файлы ------------------------------------------------------------------

def load(password):
    """Отдаёт (ключ, записи, соль)."""
    index_path = os.path.join(root(), INDEX_FILE)
    data_path = os.path.join(root(), DATA_FILE)

    if not os.path.exists(index_path):
        salt = secrets.token_bytes(16)
        return derive_key(password, salt), [], salt

    with open(index_path, encoding="utf-8") as f:
        index_file = json.load(f)
    salt = unb64(index_file["salt"])
    key = derive_key(password, salt)
    try:
        entries = unseal_index(key, index_file["index"])
    except Exception:
        raise SystemExit("индекс этим паролем не открывается")

    with open(data_path, encoding="utf-8") as f:
        items = json.load(f)["items"]

    records = []
    for entry in entries:
        try:
            record = unseal(key, items[entry["i"]])
        except Exception:
            raise SystemExit(f"фрагмент {entry['i']} не читается — индекс разошёлся с данными")
        if record is not None:
            records.append(record)
    return key, records, salt


def save(key, salt, records):
    """Пишет оба файла разом: фрагменты и индекс к ним.

    Записи лежат в том же порядке, что и в индексе, поэтому позиция в индексе
    и есть позиция фрагмента — искать нечего.
    """
    ordered = sorted(records, key=sort_key)
    items = [seal(key, record) for record in ordered]
    while len(items) % BATCH or not items:
        items.append(seal(key, None))

    entries = [{"d": r["date"], "p": r.get("pair") or r.get("time", ""), "i": i}
               for i, r in enumerate(ordered)]

    write_json(DATA_FILE, {"v": 1, "items": items})
    write_json(INDEX_FILE, {"v": 1, "salt": b64(salt), "index": seal_index(key, entries)})


def write_json(name, value):
    with open(os.path.join(root(), name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.write("\n")


# ---- записи -----------------------------------------------------------------

def sort_key(record, blank="9"):
    """Ключ порядка. blank — чем заполнять пустую пару: у нижней границы
    диапазона это «раньше всех», у верхней — «позже всех»."""
    day, month, year = (record.get("date", "").split(".") + ["", "", ""])[:3]
    return (year, month, day, record.get("pair") or blank, record.get("time", ""))


def build(args, prev=None):
    """Личная запись повторяет пару из data.json — плюс дата и id."""
    prev = prev or {}
    record = {
        "id": prev.get("id") or str(uuid.uuid4()),
        "date": args.date if args.date is not None else prev.get("date", ""),
        "pair": str(args.pair) if args.pair is not None else prev.get("pair", ""),
        "time": args.time if args.time is not None else prev.get("time", ""),
        "subject": args.subject if args.subject is not None else prev.get("subject", ""),
        "type": args.type if args.type is not None else prev.get("type", "Своё"),
        "teacher": args.teacher if args.teacher is not None else prev.get("teacher", ""),
        "room": args.room if args.room is not None else prev.get("room", ""),
        "note": args.note if args.note is not None else prev.get("note", ""),
    }
    if not record["subject"] or not record["date"]:
        raise SystemExit("обязательны --subject и --date")
    if not DATE_RE.match(record["date"]):
        raise SystemExit("дата в формате ДД.ММ.ГГГГ, как в расписании группы")
    if record["pair"] and record["pair"] not in PAIRS:
        raise SystemExit(f"номер пары один из: {', '.join(PAIRS)}")
    if not record["pair"] and not record["time"]:
        raise SystemExit("нужен либо --pair (встанет в сетку), либо --time")
    if record["type"] not in TYPES:
        raise SystemExit(f"тип один из: {', '.join(TYPES)}")
    return record


def show(records):
    if not records:
        print("пусто")
        return
    for record in records:
        pair = record.get("pair")
        when = f"{pair} пара {PAIRS[pair]}" if pair in PAIRS else (record.get("time") or "--:--")
        who = f"  {record['teacher']}" if record.get("teacher") else ""
        where = f"  ауд. {record['room']}" if record.get("room") else ""
        print(f"{record['date']}  {when}  {record['subject']}"
              f"  [{record.get('type', '')}]{who}{where}  ({record['id'][:8]})")
        if record.get("note"):
            print(f"      {record['note']}")


def find(records, ident):
    hits = [r for r in records if r["id"] == ident or r["id"].startswith(ident)]
    if not hits:
        raise SystemExit(f"запись {ident} не найдена")
    if len(hits) > 1:
        raise SystemExit(f"под {ident} подходит несколько записей — уточните id")
    return hits[0]


# ---- команды ----------------------------------------------------------------

def main():
    # Консоль Windows не в utf-8, и расшифрованное вышло бы кракозябрами.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Личное расписание: записи и индекс")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def fields(p):
        p.add_argument("--subject", help="что за занятие или дело")
        p.add_argument("--date", help="ДД.ММ.ГГГГ, как в расписании группы")
        p.add_argument("--pair", choices=tuple(PAIRS), help="номер пары: встанет в сетку недели")
        p.add_argument("--time", help="ЧЧ:ММ, если это не пара")
        p.add_argument("--type", choices=TYPES)
        p.add_argument("--teacher")
        p.add_argument("--room")
        p.add_argument("--note")

    for name, help_text in (("list", "показать записи"), ("add", "добавить"),
                            ("edit", "изменить"), ("rm", "удалить")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--password", help="иначе SCHEDULE_PASSWORD, .env или спросим")
        if name == "list":
            p.add_argument("--from", dest="date_from", help="с этой даты")
            p.add_argument("--to", dest="date_to", help="по эту дату")
        if name in ("edit", "rm"):
            p.add_argument("--id", required=True)
        if name in ("add", "edit"):
            fields(p)

    args = parser.parse_args()
    key, records, salt = load(read_password(args.password))

    if args.cmd == "list":
        chosen = records
        if args.date_from:
            chosen = [r for r in chosen if sort_key(r) >= sort_key({"date": args.date_from}, blank="")]
        if args.date_to:
            chosen = [r for r in chosen if sort_key(r) <= sort_key({"date": args.date_to, "pair": "9"})]
        show(chosen)
        return

    if args.cmd == "add":
        record = build(args)
        save(key, salt, records + [record])
        print(f"добавлена {record['id'][:8]} — {record['subject']}")
        return

    if args.cmd == "edit":
        prev = find(records, args.id)
        record = build(args, prev)
        records[records.index(prev)] = record
        save(key, salt, records)
        print(f"изменена {record['id'][:8]} — {record['subject']}")
        return

    if args.cmd == "rm":
        record = find(records, args.id)
        records.remove(record)
        save(key, salt, records)
        print(f"удалена {record['id'][:8]} — {record['subject']}")
        return


if __name__ == "__main__":
    sys.exit(main())
