# Contributing

## Layout

| Path | Module | Go |
| --- | --- | --- |
| `.` (core, `httpx/`) | `github.com/FelixMiddelhoff/spillgate` | 1.23 |
| `br/` | `.../spillgate/br` | 1.23 |
| `zstd/` | `.../spillgate/zstd` | 1.25 |
| `testsuite/` | `.../spillgate/testsuite` | 1.25 |

The core module must never get a `require`. Optional codecs live in their own modules.

## Run the checks

```
go test ./...                       # core + httpx (about 25 s; -short about 3 s)
cd br && go test ./...
cd zstd && go test ./...
cd testsuite && go test ./...       # all 353 vectors, differential, memory canaries
go run ./tools/spectrace            # every spec rule has a test
go test ./tools/gencorpus           # committed vectors equal generator output
GOARCH=386 go test -short ./...
```

CI also runs `-race`, staticcheck, gosec, govulncheck, short fuzz runs and a
nightly long fuzz run.

## Rules

- Spec first. A new rule gets an ID in `spec/SPEC.md`, a conformance vector and a unit test. `spectrace` fails otherwise.
- Test first for every bug. Never weaken a test or change an expected outcome in `conformance/manifest.json` to make code pass; outcome changes need maintainer sign-off.
- Fixed bypass means new vector. Fuzz crashers become vectors.
- Budgets are `int64`, decremented, never added and compared. Code must work with `MaxOutput = math.MaxInt64` and on 32-bit.
- Code is read by people: short functions, a doc comment on every declaration that explains why, rule IDs (`SG-R-...`) where a rule applies.
- No `unsafe`, no cgo, no new dependency in the core.

## Regenerating the corpus

Vectors are produced by `tools/gencorpus` without any compressor.
`go run ./tools/gencorpus` rewrites `conformance/`; review the diff, because
changed hashes mean changed streams.
