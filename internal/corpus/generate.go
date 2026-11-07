package corpus

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
)

// Spec describes a generated stream in the conformance manifest:
// {"kind": "...", "params": {...}}. Generation is deterministic.
//
// Kinds (see spec/generators.md):
//
//	zeros       {"codec": "gzip"|"zlib"|"raw", "matches": n}   max-ratio zeros, 1+258n bytes decoded
//	data        {"codec": "gzip"|"zlib"|"raw", "seed": s, "size": n}   stored blocks around Data(s, n)
//	wrap        {"codec": "gzip"|"zlib"|"raw", "times": k, "inner": Spec}   k stored wrappers around inner
type Spec struct {
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params"`
}

type zerosParams struct {
	Codec   string `json:"codec"`
	Matches int64  `json:"matches"`
}

type dataParams struct {
	Codec string `json:"codec"`
	Seed  uint64 `json:"seed"`
	Size  int    `json:"size"`
}

type wrapParams struct {
	Codec string `json:"codec"`
	Times int    `json:"times"`
	Inner Spec   `json:"inner"`
}

// Zeros returns the Spec of a max-ratio zeros stream.
func Zeros(codec string, matches int64) Spec {
	return mustSpec("zeros", zerosParams{Codec: codec, Matches: matches})
}

// Stored returns the Spec of a stored-block stream around Data(seed, size).
func Stored(codec string, seed uint64, size int) Spec {
	return mustSpec("data", dataParams{Codec: codec, Seed: seed, Size: size})
}

// Wrap returns the Spec of `times` stored wrappers of codec around inner.
func Wrap(codec string, times int, inner Spec) Spec {
	return mustSpec("wrap", wrapParams{Codec: codec, Times: times, Inner: inner})
}

func mustSpec(kind string, params any) Spec {
	raw, err := json.Marshal(params)
	if err != nil {
		panic(err) // the params types above always marshal
	}
	return Spec{Kind: kind, Params: raw}
}

// Generate builds the compressed stream a Spec describes.
func Generate(s Spec) ([]byte, error) {
	switch s.Kind {
	case "zeros":
		var p zerosParams
		if err := json.Unmarshal(s.Params, &p); err != nil {
			return nil, err
		}
		return zeros(p)
	case "data":
		var p dataParams
		if err := json.Unmarshal(s.Params, &p); err != nil {
			return nil, err
		}
		return wrapOnce(p.Codec, Data(p.Seed, p.Size))
	case "wrap":
		var p wrapParams
		if err := json.Unmarshal(s.Params, &p); err != nil {
			return nil, err
		}
		return wrap(p)
	default:
		return nil, fmt.Errorf("unknown generator kind %q", s.Kind)
	}
}

func zeros(p zerosParams) ([]byte, error) {
	switch p.Codec {
	case "gzip":
		return GzipZeros(p.Matches), nil
	case "zlib":
		return ZlibZeros(p.Matches), nil
	case "raw":
		return ZerosDeflate(p.Matches), nil
	}
	return nil, fmt.Errorf("unknown codec %q", p.Codec)
}

// wrapOnce wraps data in one stored stream of the given codec.
func wrapOnce(codec string, data []byte) ([]byte, error) {
	switch codec {
	case "gzip":
		return GzipStored(data), nil
	case "zlib":
		return ZlibStored(data), nil
	case "raw":
		return StoredDeflate(data), nil
	}
	return nil, fmt.Errorf("unknown codec %q", codec)
}

func wrap(p wrapParams) ([]byte, error) {
	data, err := Generate(p.Inner)
	if err != nil {
		return nil, err
	}
	for range p.Times {
		if data, err = wrapOnce(p.Codec, data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

// SHA256Hex returns the hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// ZerosSHA256Hex returns the hex SHA-256 of n zero bytes without holding them
// in memory.
func ZerosSHA256Hex(n int64) string {
	digest := sha256.New()
	writeZeros(digest, n)
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func writeZeros(w hash.Hash, n int64) {
	zeros := make([]byte, 1<<20)
	for n > 0 {
		chunk := min(n, int64(len(zeros)))
		io.Writer(w).Write(zeros[:chunk])
		n -= chunk
	}
}
