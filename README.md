# ZGuard

Privacy firewall for AI workloads: **scan, mask and gate log exports** before they reach an
AI pipeline. Built for the IBM Z datathon.

> **What ZGuard does and does not guarantee.** It lowers the likelihood that API keys, e-mail
> addresses, IPv4 addresses and user IDs leave a log export. It does **not** guarantee
> detection. **Synthetic data only**: never put real logs in this repository.

## How it works

```
input file -> rules (exact spans) --+
                                    +--> merge --> POLICY ENGINE --> ALLOW: masked copy + audit
input file -> ML line scorer -------+    (TOML)     (only decider)   BLOCK: no file, exit 1
              (probability, no span)
```

- **Rules** (`rules.py`): API keys/tokens, e-mail, IPv4, user IDs with exact character spans.
- **ML** (`ml.py`): TF-IDF + Logistic Regression scores lines the rules cannot span
  (obfuscated e-mails/IPs, pasted secrets, passwords). It never decides anything.
- **Policy** (`policy.py`, `configs/*.toml`): sole authority for ALLOW/BLOCK. Rule findings are
  masked as `[REDACTED:TYPE]`; an unmasked finding at a blocking severity (for example an ML
  line scoring above the high-risk threshold) blocks the whole export.
- **Fail-closed**: unreadable input, bad policy, missing or corrupt model => BLOCK, no output.

## Quick start

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
python scripts/reproduce.py        # generate data -> train -> evaluate (about 1 minute)
pytest -q
```

Linux / macOS / WSL: same, with `source .venv/bin/activate` (and `make reproduce` works too).

Run from the repo root (default paths are `configs/policy.toml` and `models/zguard_lr.pkl`).

## Using it

```powershell
zguard scan     data/generated/test.log -v
zguard review   data/generated/test.log
zguard sanitize examples/sample_input.log --out out/sample_output.log --audit-dir out/audit
zguard audit    examples/sample_input.log --out-dir out/audit
zguard sanitize examples/sample_blocked.log --out out/blocked.log   # BLOCK: no file, exit 1
zguard scan examples/sample_input.log --no-ml                       # rules only
zguard scan examples/sample_input.log --policy configs/policy_strict.toml
```

Exit codes: `0` ALLOW, `1` BLOCK, `2` error (also BLOCK). See `examples/` for sample before/after
files and an audit summary.

## Results

`python scripts/reproduce.py` writes `results/RESULTS.md` and `results/metrics.json`:
rules-only vs ML-only vs hybrid (precision, recall, F1, FPR), redaction misses per type,
end-to-end policy decisions, throughput and hardware. Report numbers exactly as measured,
including missed targets. Tune thresholds on the validation split (`train.py` prints
suggestions), edit `configs/policy.toml`, then run `evaluate.py` once on the test split.

## Repo layout

`src/zguard/` package | `scripts/` generate, train, evaluate, reproduce | `configs/` policies |
`tests/` pytest suite | `docs/` limitations and LinuxONE guide | `examples/` sample I/O

## Security notes

No network calls at runtime; audit output never contains raw values; models load only after
SHA-256 verification; see `SECURITY.md` and `docs/limitations.md`.

## LinuxONE (s390x)

Unverified until run and recorded: see `docs/linuxone.md`.

## Future work

Branch protection, CODEOWNERS, issue templates, Dependabot, containers, s390x smoke test in CI.

License: Apache.
