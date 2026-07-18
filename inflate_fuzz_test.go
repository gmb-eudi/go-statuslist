package statuslist

import (
	"bytes"
	"compress/zlib"
	"testing"
)

// FuzzDecompress drives (*Checker).inflate directly. It must never panic and
// must never return more than the cap.
func FuzzDecompress(f *testing.F) {
	var good bytes.Buffer
	zw := zlib.NewWriter(&good)
	_, _ = zw.Write(make([]byte, 4096))
	_ = zw.Close()
	f.Add(good.Bytes())
	f.Add([]byte{0x78, 0x9c}) // zlib header only (truncated)
	f.Add([]byte("not zlib"))
	f.Add([]byte(""))

	c := &Checker{maxDecompressed: 1 << 16}
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := c.inflate(data)
		if err == nil && len(out) > c.maxDecompressed {
			t.Fatalf("inflate returned %d bytes, exceeds cap %d", len(out), c.maxDecompressed)
		}
	})
}
