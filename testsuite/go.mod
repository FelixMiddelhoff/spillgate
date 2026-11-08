module github.com/FelixMiddelhoff/spillgate/testsuite

go 1.25

require (
	github.com/FelixMiddelhoff/spillgate v0.0.0
	github.com/FelixMiddelhoff/spillgate/br v0.0.0
	github.com/FelixMiddelhoff/spillgate/zstd v0.0.0
)

require (
	github.com/andybalholm/brotli v1.2.8 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
)

// Local development: all modules of the repository sit next to each other.
replace (
	github.com/FelixMiddelhoff/spillgate => ../
	github.com/FelixMiddelhoff/spillgate/br => ../br
	github.com/FelixMiddelhoff/spillgate/zstd => ../zstd
)
