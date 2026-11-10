# Releasing

Four Go modules live in this repository. Only the first three are published; `testsuite` is test-only and keeps its `replace` directives so it always tests the working tree.

| Module | Tag prefix | Requires |
| --- | --- | --- |
| core (`.`, includes `httpx`) | `v0.x.y` | nothing |
| `br` | `br/v0.x.y` | core |
| `zstd` | `zstd/v0.x.y` | core |

## Before tagging

1. `main` is green: `ci`, `codeql`, `scorecard`, and a recent `mutation` run.
2. `nightly-fuzz` has run on its schedule for several days without a finding.
3. `CHANGELOG.md` has the version and date, `go mod tidy` leaves no diff in any module.
4. The maintainer has said yes to this exact version. Versions at or above 1.0 need explicit, separate consent.

## Steps (order matters)

1. Tag the core and push the tag:
   ```
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
2. Pin `br` and `zstd` to it. In each of `br/go.mod` and `zstd/go.mod` set `require github.com/FelixMiddelhoff/spillgate v0.1.0` and delete the `replace` block. Then:
   ```
   cd br && go mod tidy && go test ./...
   cd ../zstd && go mod tidy && go test ./...
   ```
   Commit the two `go.mod`/`go.sum` changes to `main`.
3. Tag and push them: `git tag -a br/v0.1.0 -m "br v0.1.0"`, `git tag -a zstd/v0.1.0 -m "zstd v0.1.0"`, `git push origin br/v0.1.0 zstd/v0.1.0`.
4. Check from a clean directory that consumers can fetch them:
   ```
   mkdir t && cd t && go mod init t
   go get github.com/FelixMiddelhoff/spillgate@v0.1.0 github.com/FelixMiddelhoff/spillgate/br@v0.1.0 github.com/FelixMiddelhoff/spillgate/zstd@v0.1.0
   ```
5. Create the GitHub release from the core tag with the changelog text.

## Working on the modules together afterwards

With the `replace` directives gone, `br` and `zstd` build against the published core. To develop all of them at once use a local workspace that is not committed:

```
go work init . ./br ./zstd ./testsuite
```

`go.work` is in `.gitignore`.

## Never

Never move or delete a published tag. A wrong release gets a new patch version.
