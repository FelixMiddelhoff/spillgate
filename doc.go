// Package spillgate decodes untrusted compressed data under mandatory limits.
//
// A decompression bomb is a small input that expands to an enormous output.
// spillgate stops it at the gate: every decoding layer has a hard output
// limit, an expansion-ratio limit and a bounded chain length, and anything
// that exceeds a limit ends in a typed error, never in silent truncation.
//
// The normative rules live in spec/SPEC.md; rule IDs such as SG-R-LAY-03 in
// comments point there. The main building blocks are:
//
//   - Limits and its validation (limits.go): what the caller asks for.
//   - Error and Kind (errors.go): how a refusal is reported.
//   - inputMeter (meter.go): counts the compressed bytes a codec consumes.
//   - layerGuard (guard.go): wraps one codec's output and enforces the limits.
//
// Design principle: when in doubt, refuse. The only failure mode of a bug
// should be a denial of service, never data exposure or file access.
package spillgate
