# ZGuard evaluation (synthetic data, as measured)

Policy mode `standard`, ML thresholds review/high = [0.5, 0.85].

## Line-level detection

| System | Precision | Recall | F1 | FPR | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|---|
| rules_only | 1.0 | 0.5325 | 0.6949 | 0.0 | 82 | 0 | 72 | 246 |
| ml_only | 1.0 | 1.0 | 1.0 | 0.0 | 154 | 0 | 0 | 246 |
| hybrid | 1.0 | 1.0 | 1.0 | 0.0 | 154 | 0 | 0 | 246 |

## Span-level redaction by the rule layer

| Gold type | Gold spans | Caught | Exact span | Missed |
|---|---|---|---|---|
| API_KEY | 61 | 33 | 33 | 28 |
| EMAIL | 45 | 30 | 30 | 15 |
| IPV4 | 37 | 23 | 23 | 14 |
| SECRET | 15 | 0 | 0 | 15 |
| USER_ID | 20 | 20 | 20 | 0 |

Redaction misses by rules: **72** of 178 gold spans. Lines with a miss: 72; of those, ML flags 72 for review and 72 at BLOCK level.

## End-to-end policy decision

| System | Full test file | Clean subset |
|---|---|---|
| rules_only | ALLOW (0 blocking) | ALLOW (0 blocking) |
| hybrid | BLOCK (72 blocking) | ALLOW (0 blocking) |

## Throughput

5000 lines: rules-only 0.13 s, hybrid 0.59 s (8431 lines/s). Target (100k lines < 60 s): not met / not tested at 100k.

## Hardware and versions

- machine: s390x
- processor: s390x
- system: Linux-6.8.0-124-generic-s390x-with-glibc2.39
- python: 3.12.3
- sklearn: 1.4.1.post1
- numpy: 1.26.4
- byteorder: big
- model_sha256: 4f63a6973d568d6b51778572a2ea9057faff7172b6533c7cd98722c0521016fd

Synthetic data is easier than real logs; see docs/limitations.md.
