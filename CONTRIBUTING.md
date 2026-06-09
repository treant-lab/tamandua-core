# Contributing to tamandua-core

This component is part of the Tamandua EDR platform. For the canonical
contribution guide — code of conduct, contribution tracks, and community
norms — see the community repository:

  https://github.com/treant-lab/tamandua-community

Please also read this component's [README](./README.md) for details.

## Component build & test

```bash
cargo build
cargo test
cargo clippy --all-targets
```

## Before opening a PR

- This crate is dual-licensed MIT OR Apache-2.0; contributions are accepted under the same dual license.
- Keep changes scoped; avoid unrelated refactors.
- Do not commit secrets or large binaries.
- Do not fabricate or overstate results; preserve benchmark caveats verbatim.
