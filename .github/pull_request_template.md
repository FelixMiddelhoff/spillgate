## What and why

## Checklist
- [ ] Test written first; it failed before the change
- [ ] New or changed rule: spec/SPEC.md, a conformance vector and a test with the ID in its doc comment
- [ ] No expected outcome in conformance/manifest.json weakened
- [ ] `go test ./...` in every touched module, `go run ./tools/spectrace`
- [ ] Core module still has no `require`
