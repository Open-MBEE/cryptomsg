package kdf

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

// Vectors from the ANSI X9.63-2001 KDF conformance set as published in
// NIST CAVP (ANS X9.63-2001 KDF, SHA-256 and SHA-384, no SharedInfo).
func TestX963Vectors(t *testing.T) {
	cases := []struct {
		name  string
		hash  func() []byte
		z     string
		info  string
		bits  int
		wantK string
	}{
		{
			name:  "SHA-256, 128-bit output",
			hash:  nil,
			z:     "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
			info:  "",
			bits:  128,
			wantK: "443024c3dae66b95e6f5670601558f71",
		},
		{
			name:  "SHA-256, 128-bit output with SharedInfo",
			hash:  nil,
			z:     "22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d",
			info:  "75eef81aa3041e33b80971203d2c0c52",
			bits:  1024,
			wantK: "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5ea0bc7b00e0da2447cfd874f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd496269142d43525a78e5bc79a17f59676a5706dc54d54d4d1f0bd7e386128ec26afc21",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			z, _ := hex.DecodeString(c.z)
			info, _ := hex.DecodeString(c.info)
			want, _ := hex.DecodeString(c.wantK)
			got, err := X963(sha256.New, z, info, c.bits/8)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %x, %v\nwant %x", got, err, want)
			}
		})
	}
}

func TestX963Properties(t *testing.T) {
	z := []byte("shared secret")
	a, _ := X963(sha512.New384, z, nil, 48)
	b, _ := X963(sha512.New384, z, nil, 96)
	if !bytes.Equal(a, b[:48]) {
		t.Fatal("output must be a prefix-consistent counter stream")
	}
	c, _ := X963(sha512.New384, z, []byte{1}, 48)
	if bytes.Equal(a, c) {
		t.Fatal("SharedInfo must change the output")
	}
	if out, err := X963(sha256.New, z, nil, 0); err != nil || len(out) != 0 {
		t.Fatalf("zero length: %x, %v", out, err)
	}
	if _, err := X963(sha256.New, z, nil, 32*0xffffffff+1); err != ErrLength {
		t.Fatalf("oversized: %v", err)
	}
}
