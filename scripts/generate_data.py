"""Generate seeded synthetic data (train/val/test .jsonl plus test.log)."""

import argparse

from zguard.synth import make_splits


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/generated")
    ap.add_argument("--n-train", type=int, default=6000)
    ap.add_argument("--n-val", type=int, default=1500)
    ap.add_argument("--n-test", type=int, default=1500)
    a = ap.parse_args()
    make_splits(a.out, a.seed, a.n_train, a.n_val, a.n_test)
    print(f"wrote synthetic splits to {a.out} (seed={a.seed})")


if __name__ == "__main__":
    main()
