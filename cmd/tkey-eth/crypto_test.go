package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestDecodeHexString(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
		err  bool
	}{
		{"0x1234", []byte{0x12, 0x34}, false},
		{"1234", []byte{0x12, 0x34}, false},
		{"0x0", []byte{0x00}, false},
		{"0xdeadbeef", []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"zz", nil, true},
	}
	for _, c := range cases {
		got, err := decodeHexString(c.in)
		if c.err {
			if err == nil {
				t.Errorf("decodeHexString(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("decodeHexString(%q): %v", c.in, err)
			continue
		}
		if hex.EncodeToString(got) != hex.EncodeToString(c.want) {
			t.Errorf("decodeHexString(%q) = %x, want %x", c.in, got, c.want)
		}
	}
}

func TestDecodeHex32(t *testing.T) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	s := "0x" + hex.EncodeToString(b)
	got, err := decodeHex32(s)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != hex.EncodeToString(b) {
		t.Fatalf("got %x, want %x", got, b)
	}

	if _, err = decodeHex32("0x1234"); err == nil {
		t.Fatal("expected error for 2-byte input")
	}
	if _, err = decodeHex32("0x" + hex.EncodeToString(make([]byte, 33))); err == nil {
		t.Fatal("expected error for 33-byte input")
	}
}

func rawPubkey(priv *ecdsa.PrivateKey) []byte {
	pub := priv.Public().(*ecdsa.PublicKey)
	raw := make([]byte, 64)
	xb := pub.X.Bytes()
	yb := pub.Y.Bytes()
	copy(raw[32-len(xb):32], xb)
	copy(raw[64-len(yb):], yb)
	return raw
}

func TestEthereumAddress(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(*ecdsa.PublicKey)
	want := crypto.PubkeyToAddress(*pub)

	addr, err := ethereumAddress(rawPubkey(priv))
	if err != nil {
		t.Fatal(err)
	}
	if addr != want {
		t.Fatalf("got %s, want %s", addr, want)
	}

	if _, err = ethereumAddress(make([]byte, 63)); err == nil {
		t.Fatal("expected error for wrong pubkey length")
	}
}

func TestFinalizeEthereumSignature(t *testing.T) {
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(*ecdsa.PublicKey)
	want := crypto.PubkeyToAddress(*pub)
	pubRaw := rawPubkey(priv)

	digest := make([]byte, 32)
	if _, err = rand.Read(digest); err != nil {
		t.Fatal(err)
	}

	// go-ethereum's Sign produces a 65-byte sig (r || s || v); take the first 64.
	sig65, err := crypto.Sign(digest, priv)
	if err != nil {
		t.Fatal(err)
	}
	rawSig := sig65[:64]

	ethSig, addr, err := finalizeEthereumSignature(digest, pubRaw, rawSig)
	if err != nil {
		t.Fatalf("finalizeEthereumSignature: %v", err)
	}
	if addr != want {
		t.Fatalf("address: got %s, want %s", addr, want)
	}
	if len(ethSig) != 65 {
		t.Fatalf("ethSig length %d, want 65", len(ethSig))
	}

	// Verify the finalized signature recovers the right address.
	if err = verifyRecoveredSignature(digest, ethSig, addr); err != nil {
		t.Fatalf("verifyRecoveredSignature: %v", err)
	}
}

func TestFinalizeEthereumSignature_LowS(t *testing.T) {
	// Construct a signature with high s and verify it is normalized to low s.
	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubRaw := rawPubkey(priv)

	digest := make([]byte, 32)
	if _, err = rand.Read(digest); err != nil {
		t.Fatal(err)
	}

	sig65, err := crypto.Sign(digest, priv)
	if err != nil {
		t.Fatal(err)
	}
	rawSig := make([]byte, 64)
	copy(rawSig, sig65[:64])

	// Flip s to its complement (curveN - s), making it high-s.
	const secp256k1NHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	curveN, _ := new(big.Int).SetString(secp256k1NHex, 16)
	s := new(big.Int).SetBytes(rawSig[32:])
	highS := new(big.Int).Sub(curveN, s)
	sb := highS.Bytes()
	copy(rawSig[32:], make([]byte, 32))
	copy(rawSig[64-len(sb):], sb)

	ethSig, addr, err := finalizeEthereumSignature(digest, pubRaw, rawSig)
	if err != nil {
		t.Fatalf("finalizeEthereumSignature with high-s: %v", err)
	}
	if err = verifyRecoveredSignature(digest, ethSig, addr); err != nil {
		t.Fatalf("verifyRecoveredSignature after high-s normalization: %v", err)
	}
}
