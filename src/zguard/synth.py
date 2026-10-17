"""Seeded synthetic log generator with gold labels and exact gold spans.

Everything here is fake. No real logs, keys, e-mails or IPs are used.
Kinds: clean, hard_negative (looks sensitive, is not), rule_pos (rules can span it),
obfuscated_pos (sensitive, but written so regexes cannot span it: the ML layer's job).
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

SERVICES = ["auth-svc", "billing", "gateway", "inventory", "report-job", "search", "notify"]
FIRST = ["jane", "omar", "li", "priya", "carlos", "anna", "ken", "sara", "tom", "mei"]
LAST = ["doe", "khan", "wang", "patel", "silva", "novak", "ito", "ali", "ford", "chen"]
DOMAINS = ["example.com", "mail.test", "corp.example.org", "demo.net", "sample.io"]
ALNUM = string.ascii_letters + string.digits


def _ts(r: random.Random) -> str:
    return (
        f"2026-{r.randint(1, 9):02d}-{r.randint(1, 28):02d}T"
        f"{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}Z"
    )


def _token(r: random.Random, n: int) -> str:
    chars = [r.choice(ALNUM) for _ in range(n)]
    chars[r.randrange(n)] = r.choice(string.digits)
    chars[r.randrange(n)] = r.choice(string.ascii_letters)
    if not any(c.isdigit() for c in chars):
        chars[0] = "7"
    return "".join(chars)


def _email(r: random.Random) -> str:
    sep = r.choice([".", "_", ""])
    return f"{r.choice(FIRST)}{sep}{r.choice(LAST)}{r.randint(1, 99)}@{r.choice(DOMAINS)}"


def _ip(r: random.Random) -> str:
    return f"{r.randint(11, 223)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"


def _uid(r: random.Random) -> str:
    return f"U{r.randint(100000, 999999)}"


def _password(r: random.Random) -> str:
    pool = string.ascii_letters + string.digits + "!#$%&*"
    return "".join(r.choice(pool) for _ in range(r.randint(10, 14))) + str(r.randint(1, 9))


def _build(parts: list) -> tuple[str, list[dict]]:
    text, spans = "", []
    for p in parts:
        if isinstance(p, str):
            text += p
        else:
            ftype, value = p
            spans.append({"type": ftype, "start": len(text), "end": len(text) + len(value)})
            text += value
    return text, spans


def _clean(r: random.Random) -> list:
    ts, svc, n = _ts(r), r.choice(SERVICES), r.randint(1, 9999)
    return [
        r.choice(
            [
                f"{ts} INFO {svc} request completed status=200 duration_ms={n}",
                f"{ts} DEBUG {svc} cache hit ratio {r.random():.2f} for shard {n % 16}",
                f"{ts} WARN {svc} retrying connection attempt {n % 5 + 1} of 5",
                f"{ts} INFO {svc} batch job job-{n} finished rows={n * 3}",
                f"{ts} ERROR {svc} timeout calling inventory endpoint after {n} ms",
                f"{ts} INFO {svc} deployed version {n % 9}.{n % 20}.{n % 7} build {n:05x}",
                f"{ts} INFO {svc} health check ok uptime_s={n * 60}",
                f"{ts} DEBUG {svc} queue length {n % 300} workers={n % 12 + 1}",
                f"{ts},{svc},{n},ok,{r.randint(1, 900)}ms",
            ]
        )
    ]


def _hard_negative(r: random.Random) -> list:
    ts, svc, n = _ts(r), r.choice(SERVICES), r.randint(1, 999)
    return [
        r.choice(
            [
                f"{ts} INFO {svc} token bucket refill rate set to {n} per second",
                f"{ts} INFO {svc} password policy updated: minimum length {n % 8 + 8}",
                f"{ts} INFO {svc} email queue depth {n} messages pending",
                f"{ts} INFO {svc} ip allowlist reloaded with {n} entries",
                f"{ts} INFO {svc} release {n % 9}.{n % 5}.{n % 3}.{n % 7}.{n % 4} tagged",
                f"{ts} INFO {svc} api_key=<redacted> rotation scheduled in {n} minutes",
                f"{ts} WARN {svc} user_id=null request was unauthenticated",
                f"{ts} INFO {svc} secret rotation job completed in {n} ms",
                f"{ts} INFO {svc} session expired, issuing a new one for the client",
                f"{ts} WARN {svc} invalid address 999.{n}.1.1 rejected by validator",
                f"{ts} INFO {svc} contact the support team through the help portal",
                f"{ts} INFO {svc} downloaded report_{n}.csv from the storage bucket",
                f"{ts} INFO {svc} customer wrote from the web form asking for a refund",
                f"{ts} WARN {svc} credential pasted into support chat was removed by moderator",
                f"{ts} INFO {svc} temporary password for new hire must be {n % 8 + 8} characters",
                f"{ts} WARN {svc} suspicious traffic from a known scanner blocked at the edge",
                f"{ts} INFO {svc} user shared a screenshot in ticket TCK-{n}",
            ]
        )
    ]


def _rule_pos(r: random.Random) -> list:
    ts, svc = _ts(r), r.choice(SERVICES)
    c = r.randrange(9)
    if c == 0:
        return [f"{ts} INFO {svc} password reset email sent to ", ("EMAIL", _email(r))]
    if c == 1:
        return [
            f"{ts} WARN {svc} failed login from ",
            ("IPV4", _ip(r)),
            f" after {r.randint(2, 9)} tries",
        ]
    if c == 2:
        return [f"{ts} DEBUG {svc} header Authorization: Bearer ", ("API_KEY", _token(r, 32))]
    if c == 3:
        return [
            f"{ts} INFO {svc} loaded config api_key=",
            ("API_KEY", _token(r, r.randint(20, 40))),
            " from env",
        ]
    if c == 4:
        return [f"{ts} ERROR {svc} credential rejected: ", ("API_KEY", "zgk_test_" + _token(r, 24))]
    if c == 5:
        return [f"{ts} INFO {svc} profile updated user_id=", ("USER_ID", _uid(r)), " fields=2"]
    if c == 6:
        return [
            '{"ts":"' + ts + '","svc":"' + svc + '","event":"login","user_id":"',
            ("USER_ID", _uid(r)),
            '","ip":"',
            ("IPV4", _ip(r)),
            '"}',
        ]
    if c == 7:
        return [
            f"{ts} INFO {svc} invoice sent to ",
            ("EMAIL", _email(r)),
            " account_id=",
            ("USER_ID", _uid(r)),
        ]
    return [f"{ts},{svc},", ("EMAIL", _email(r)), ",", ("IPV4", _ip(r)), f",{r.randint(1, 500)}"]


def _obfuscated_pos(r: random.Random) -> list:
    ts, svc = _ts(r), r.choice(SERVICES)
    c = r.randrange(5)
    if c == 0:
        mail = (
            f"{r.choice(FIRST)} dot {r.choice(LAST)} at {r.choice(DOMAINS).replace('.', ' dot ')}"
        )
        return [f"{ts} INFO {svc} customer wrote from ", ("EMAIL", mail), " asking for a refund"]
    if c == 1:
        ip = " dot ".join(_ip(r).split("."))
        return [f"{ts} WARN {svc} suspicious traffic from host ", ("IPV4", ip), " flagged"]
    if c == 2:
        return [
            f"{ts} DEBUG {svc} credential pasted into support chat: ",
            ("API_KEY", _token(r, 28)),
        ]
    if c == 3:
        return [f"{ts} INFO {svc} temporary password for new hire is ", ("SECRET", _password(r))]
    return [
        f"{ts} WARN {svc} user shared their login secret in ticket: ",
        ("API_KEY", _token(r, 30)),
    ]


_KINDS = [
    ("clean", 0.50, _clean, 0),
    ("hard_negative", 0.15, _hard_negative, 0),
    ("rule_pos", 0.20, _rule_pos, 1),
    ("obfuscated_pos", 0.15, _obfuscated_pos, 1),
]


def generate(n: int, seed: int, exclude: set[str] | None = None) -> list[dict]:
    """Return n records: {text, label, spans, kind}. Deterministic for a given seed."""
    r = random.Random(seed)
    seen = exclude if exclude is not None else set()
    weights = [k[1] for k in _KINDS]
    records: list[dict] = []
    while len(records) < n:
        kind, _, fn, label = r.choices(_KINDS, weights=weights)[0]
        text, spans = _build(fn(r))
        if text in seen:
            continue
        seen.add(text)
        records.append({"text": text, "label": label, "spans": spans, "kind": kind})
    return records


def write_jsonl(path: str | Path, records: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def read_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def make_splits(out_dir: str | Path, seed: int, n_train: int, n_val: int, n_test: int) -> None:
    """Disjoint train/val/test splits (no identical lines across splits) plus test.log."""
    out_dir = Path(out_dir)
    seen: set[str] = set()
    for name, n, offset in (("train", n_train, 0), ("val", n_val, 1), ("test", n_test, 2)):
        recs = generate(n, seed + offset, seen)
        write_jsonl(out_dir / f"{name}.jsonl", recs)
        if name == "test":
            with open(out_dir / "test.log", "w", encoding="utf-8", newline="\n") as f:
                f.writelines(rec["text"] + "\n" for rec in recs)
