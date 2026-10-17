"""Cross-platform replacement for 'make reproduce': generate -> train -> evaluate."""

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(script: str, *args: str) -> None:
    cmd = [sys.executable, str(HERE / script), *args]
    print("\n$", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seed", default="42")
    ap.add_argument("--quick", action="store_true", help="small sizes (used by CI)")
    a = ap.parse_args()
    sizes = ["--n-train", "1500", "--n-val", "400", "--n-test", "400"] if a.quick else []
    bench = "5000" if a.quick else "100000"
    run("generate_data.py", "--seed", a.seed, "--out", "data/generated", *sizes)
    run("train.py", "--data", "data/generated", "--out", "models", "--seed", a.seed)
    run("evaluate.py", "--data", "data/generated", "--model", "models/zguard_lr.pkl",
        "--out", "results", "--bench-lines", bench)  # fmt: skip


if __name__ == "__main__":
    main()
