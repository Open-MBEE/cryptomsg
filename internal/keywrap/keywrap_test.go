package keywrap

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"errors"
	"testing"
)

// RFC 3394 §4 test vectors.
var rfc3394 = []struct{ name, kek, key, wrapped string }{
	{"4.1 128 bits of key data with a 128-bit KEK",
		"000102030405060708090A0B0C0D0E0F",
		"00112233445566778899AABBCCDDEEFF",
		"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
	{"4.2 128 bits of key data with a 192-bit KEK",
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"00112233445566778899AABBCCDDEEFF",
		"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
	{"4.3 128 bits of key data with a 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF",
		"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
	{"4.4 192 bits of key data with a 192-bit KEK",
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"00112233445566778899AABBCCDDEEFF0001020304050607",
		"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"},
	{"4.5 192 bits of key data with a 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF0001020304050607",
		"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"},
	{"4.6 256 bits of key data with a 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"},
}

func TestRFC3394Vectors(t *testing.T) {
	for _, v := range rfc3394 {
		t.Run(v.name, func(t *testing.T) {
			kek, _ := hex.DecodeString(v.kek)
			key, _ := hex.DecodeString(v.key)
			wrapped, _ := hex.DecodeString(v.wrapped)
			block, err := aes.NewCipher(kek)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Wrap(block, key)
			if err != nil || !bytes.Equal(got, wrapped) {
				t.Fatalf("Wrap = %X, %v; want %X", got, err, wrapped)
			}
			back, err := Unwrap(block, wrapped)
			if err != nil || !bytes.Equal(back, key) {
				t.Fatalf("Unwrap = %X, %v; want %X", back, err, key)
			}
		})
	}
}

func TestUnwrapRejects(t *testing.T) {
	kek, _ := hex.DecodeString(rfc3394[0].kek)
	wrapped, _ := hex.DecodeString(rfc3394[0].wrapped)
	block, _ := aes.NewCipher(kek)
	for i := range wrapped {
		bad := bytes.Clone(wrapped)
		bad[i] ^= 0x01
		if out, err := Unwrap(block, bad); !errors.Is(err, ErrIntegrity) || out != nil {
			t.Fatalf("bit flip at %d: got %X, %v", i, out, err)
		}
	}
	otherKEK, _ := aes.NewCipher(bytes.Repeat([]byte{9}, 16))
	if _, err := Unwrap(otherKEK, wrapped); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong KEK: %v", err)
	}
	for _, n := range []int{0, 8, 16, 23, 25} {
		if _, err := Unwrap(block, make([]byte, n)); !errors.Is(err, ErrKeyLength) {
			t.Errorf("unwrap length %d: %v", n, err)
		}
	}
	for _, n := range []int{0, 8, 15, 17} {
		if _, err := Wrap(block, make([]byte, n)); !errors.Is(err, ErrKeyLength) {
			t.Errorf("wrap length %d: %v", n, err)
		}
	}
}
