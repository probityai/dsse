# Instructions for coding agents

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; these are the rules an agent most often breaks here.

- `cargo test`, `cargo clippy --all-targets -- -D warnings` and `cargo doc` must pass with no
  warnings before you push.
- A change to what the crate accepts comes with a test that fails without it.
- Never regenerate the pinned material from this crate: the cross-language fixtures in `vectors/`
  come from an independent Go implementation, and the vector in `tests/spec_vector.rs` from DSSE's
  protocol document. [PROVENANCE.md](PROVENANCE.md) records each source.
- `verify` returns the payload it checked. Don't add a path that reads the payload from the
  envelope after verification.
- Sign off every commit (`git commit -s`); the DCO check refuses a commit without it.
- Keep `README.md` to the first screen. Detail goes in `docs/`, and `scripts/readme-lint.py`
  fails a README over its word limit.
