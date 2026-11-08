module github.com/FelixMiddelhoff/spillgate/zstd

go 1.25

require (
	github.com/FelixMiddelhoff/spillgate v0.0.0
	github.com/klauspost/compress v1.20.3
)

// Local development: the core module sits next to this one. Replace
// directives are ignored by modules that depend on this one; before a release
// the requirement is pinned to a tagged version of the core module.
replace github.com/FelixMiddelhoff/spillgate => ../
