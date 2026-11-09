# Security policy

## Reporting a vulnerability

Use GitHub private vulnerability reporting: the repository's **Security** tab,
**Report a vulnerability**. Please do not open a public issue for a bypass.

A bypass is any input that makes the library deliver more than the configured
limits, pass an unsupported or malformed encoding through, crash the process,
or use memory that grows with the output instead of staying bounded.

What to expect:

- acknowledgment within 3 business days
- coordinated disclosure, up to 90 days from the report
- credit in the advisory if you want it
- no bug bounty

Every fixed bypass becomes a permanent conformance vector.

## Supported versions

The latest release only.

## Scope

The limits, header parsing, gzip/deflate framing, the br and zstd wrappers and
the httpx adapter are in scope. Memory-safety bugs inside third-party codec
libraries are reported upstream; tell us as well if the limiter should have
contained them. Out of scope are the items listed under "What it does not
cover" in the README and in [docs/threat-model.md](docs/threat-model.md).
