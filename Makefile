# Windows without make: use "python scripts/reproduce.py" instead.
PY ?= python
export LC_ALL = C.UTF-8
export PYTHONHASHSEED = 0

.PHONY: install test lint reproduce demo
install:
	$(PY) -m pip install -e ".[dev]"
lint:
	ruff check .
test:
	pytest -q
reproduce:
	$(PY) scripts/reproduce.py
demo:
	zguard sanitize examples/sample_input.log --out out/sample_output.log --audit-dir out/audit
