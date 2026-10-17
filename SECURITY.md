# Security notes

- ZGuard lowers the likelihood of sensitive data leaving a log export. It does not guarantee detection.
- Fail-closed: unreadable input, bad policy, or a missing/corrupt model means BLOCK and no output file.
- No network calls at runtime (checked by a test that disables sockets).
- The model is loaded with `pickle` only after its SHA-256 matches `<model>.pkl.sha256`.
  Only load models you trained yourself. Never load a model from an untrusted source.
- Audit files contain types, line numbers and truncated HMAC fingerprints, never raw values.
  Fingerprints use a random per-run key unless `ZGUARD_HMAC_KEY` is set.
- `ZGUARD_DEBUG=1` prints Python tracebacks that may contain scanned values. Do not use it on real data.
- Use synthetic data only in this repository and on shared machines.

Report issues by opening a private security advisory on the repository.
