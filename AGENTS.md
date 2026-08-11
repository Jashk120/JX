# AGENTS.md

This document defines the development rules for contributors and AI coding agents.

## General Principles

- Make the smallest correct change.
- Understand the existing architecture before modifying it.
- Match the existing coding style.
- Do not introduce unnecessary dependencies.
- Do not rewrite unrelated code.
- Leave the repository in a buildable state.

---

## Before Implementing Any Plan

1. Read the plan document fully.
2. Read the relevant source files.
3. Cross-check the plan's assumptions against the actual code.
4. List any mismatches, ambiguities, or unresolved questions and raise them
   to the user before writing a single line of implementation.
5. Do not resolve open questions by reasoning through them independently.
   Ask instead.

---
## During Implementation

- Treat decisions stated in the plan as closed. Do not re-examine them.
- If you encounter something the plan did not anticipate, stop and ask.
- Do not think through alternatives silently — surface them immediately.

---

# Formatting

Always format Rust code using the nightly formatter.

```bash
cargo +nightly fmt --all
```

Never use stable `cargo fmt` unless explicitly instructed.

---

# Linting

Run Clippy before considering work complete.

```bash
cargo clippy --workspace --all-targets
```

Fix warnings whenever practical.

---

# Testing

Run the smallest relevant test first.

Examples:

```bash
cargo test <test_name>
```

Before finishing larger changes:

```bash
cargo test --workspace
```

Do not claim code works unless the relevant tests have passed.

---

# Git

Every commit must be signed.

Use:

```bash
git commit -s -S -m "commit message"
```

Meaning:

- `-s` → Developer Certificate of Origin (Signed-off-by)
- `-S` → GPG signing

Never create unsigned commits unless explicitly requested.

Write commit messages in the imperative mood.

Examples:

- Fix race condition in consensus
- Add validation for gossip events
- Refactor signature verification

---

# Code Style

Prefer:

- Small functions
- Descriptive names
- Early returns
- Immutable variables where possible

Avoid:

- Large nested blocks
- Unnecessary cloning
- Panic unless unrecoverable
- Magic numbers

---

# Documentation

When changing public APIs:

- Update documentation.
- Update examples if needed.
- Keep comments synchronized with implementation.

---

# Dependencies

Before adding a new dependency:

- Check whether the functionality already exists in the project.
- Prefer the standard library.
- Keep dependency count minimal.

---

# Performance

Avoid unnecessary:

- allocations
- cloning
- locking
- heap usage

Consider algorithmic complexity before optimizing micro-performance.

---

# Safety

Never disable:

- Clippy lints
- compiler warnings
- safety checks

Do not use:

```rust
unwrap()
expect()
```

in library code unless failure is truly impossible or explicitly justified.

---

# Before Finishing

Always run:

```bash
cargo +nightly fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

If one of these cannot be run, explicitly state why.

---

# Pull Requests

Before opening a PR:

- Ensure formatting passes.
- Ensure linting passes.
- Ensure tests pass.
- Keep commits focused.
- Avoid unrelated changes.

---

# Communication

Never claim:

- "fixed"
- "works"
- "passes"

unless verified.

Instead say:

- Verified with `cargo test`
- Verified with `cargo clippy`
- Unable to verify because ...

Always distinguish between assumptions and verified facts.