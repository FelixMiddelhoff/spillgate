module github.com/FelixMiddelhoff/spillgate/testsuite

go 1.25

require (
	github.com/FelixMiddelhoff/spillgate v0.1.0
	github.com/FelixMiddelhoff/spillgate/br v0.0.0
	github.com/FelixMiddelhoff/spillgate/zstd v0.0.0
	github.com/andybalholm/brotli v1.2.8
	github.com/klauspost/compress v1.20.3
	go.uber.org/goleak v1.3.0
)

// Local development: all modules of the repository sit next to each other.
replace (
	github.com/FelixMiddelhoff/spillgate => ../
	github.com/FelixMiddelhoff/spillgate/br => ../br
	github.com/FelixMiddelhoff/spillgate/zstd => ../zstd
)
