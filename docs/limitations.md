# Limitations

1. **No guarantee.** ZGuard lowers the likelihood of exposure; it does not guarantee detection.
2. **Synthetic data only.** All results come from a seeded generator whose templates are easier
   than real logs. Near-perfect ML scores on this data say little about real-world accuracy.
   The ML layer learns phrasing (for example "password for new hire is ..."), so unseen phrasings
   can be missed.
3. **Four rule types only:** API keys/tokens, e-mail, IPv4, user IDs. No IPv6, phone numbers,
   names, addresses or card numbers. Labeled `user_id=` style IDs only; bare IDs are not found.
4. **ML has no spans.** It can flag a line but cannot mask it, so a flagged line leads to
   review or BLOCK, never to partial masking.
5. **One bad line can block a whole file** by design (fail-closed). Tune thresholds on the
   validation set, not the test set.
6. **Line-based scanning.** CSV and JSONL are scanned as text lines. A value split across lines
   is not detected. Input must be UTF-8.
7. **Thresholds** in `configs/policy.toml` are defaults; frozen values must be chosen on the
   validation split before evaluating on the test split.
8. **LinuxONE (s390x).** Native execution is unverified until you run it and record the result
   (see `docs/linuxone.md`). Do not claim LinuxONE security or performance benefits beyond
   what you measure.
9. Fingerprints use a per-run random key by default, so they are not comparable across runs.
