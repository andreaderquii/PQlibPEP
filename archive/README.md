# Research archive

Historical implementations are kept in `old_implementations/` for provenance and
for the report's design exploration. They are not required by the active TFHE
pipeline and are not discovered as Rust modules, integration tests or examples.

They remain visible and versioned. Prefixing a directory with a dot or adding it
to `.gitignore` is not a build-system boundary and is unnecessary here.

Do not run these files as if they were current validated targets: they may refer
to old APIs. The active foundational RLWE/RNS arithmetic and clear-reference
modules remain in `src/` because current tests and legacy diagnostic APIs use them.
