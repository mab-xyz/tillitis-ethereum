package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tillitis/tkeyclient"
)

// buildTestCert creates a well-formed, self-signed certificate for use in tests.
func buildTestCert(t *testing.T) (certificate, ed25519.PrivateKey) {
	t.Helper()

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubRaw := rawPubkey(priv)
	addr, err := ethereumAddress(pubRaw)
	if err != nil {
		t.Fatal(err)
	}

	udi := &tkeyclient.UDI{VendorID: 0x0001, ProductID: 0x01, ProductRevision: 0x00, Serial: 0xdeadbeef}

	pub, attestPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cert := certificate{
		Schema:                   certSchema,
		AttestMode:               selfAssertedMode,
		UDI:                      udiHexBE(*udi),
		VendorID:                 udi.VendorID,
		ProductID:                udi.ProductID,
		ProductRev:               udi.ProductRevision,
		WalletApp:                walletAppInfo{Name0: "eth ", Name1: "sign", Version: 1, DigestSHA256: hex.EncodeToString(make([]byte, 32))},
		WalletPubkeyUncompressed: "0x04" + hex.EncodeToString(pubRaw),
		WalletAddress:            addr.Hex(),
		USS:                      ussInfo{Mode: "none"},
		IssuedAt:                 "2026-01-01T00:00:00Z",
		AttestKeyType:            "ed25519",
		AttestPubkey:             hex.EncodeToString([]byte(pub)),
	}

	payload, err := encodeCertificatePayload(cert)
	if err != nil {
		t.Fatal(err)
	}
	payloadHash := sha256.Sum256(payload)
	cert.PayloadHashSHA256 = hex.EncodeToString(payloadHash[:])
	cert.AttestSignature = hex.EncodeToString(ed25519.Sign(attestPriv, payloadHash[:]))
	return cert, attestPriv
}

func TestEncodeCertificatePayload_Deterministic(t *testing.T) {
	cert, _ := buildTestCert(t)

	p1, err := encodeCertificatePayload(cert)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := encodeCertificatePayload(cert)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(p1) != hex.EncodeToString(p2) {
		t.Fatal("encodeCertificatePayload is not deterministic")
	}
}

func TestVerifyCertificate_Valid(t *testing.T) {
	cert, _ := buildTestCert(t)
	if err := verifyCertificate(cert); err != nil {
		t.Fatalf("verifyCertificate: %v", err)
	}
}

func TestVerifyCertificate_WrongSchema(t *testing.T) {
	cert, _ := buildTestCert(t)
	cert.Schema = "wrong-schema"
	if err := verifyCertificate(cert); err == nil {
		t.Fatal("expected error for wrong schema")
	}
}

func TestVerifyCertificate_TamperedAddress(t *testing.T) {
	cert, _ := buildTestCert(t)
	// Replace wallet address with a different one — cert signature still valid,
	// but address/pubkey consistency check must fail.
	cert.WalletAddress = "0x0000000000000000000000000000000000000001"
	if err := verifyCertificate(cert); err == nil {
		t.Fatal("expected error for tampered wallet address")
	}
}

func TestVerifyCertificate_TamperedPayload(t *testing.T) {
	cert, _ := buildTestCert(t)
	cert.WalletApp.Version = 99 // change a payload field after signing
	if err := verifyCertificate(cert); err == nil {
		t.Fatal("expected error for tampered payload field")
	}
}

func TestVerifyCertificate_BadSignature(t *testing.T) {
	cert, _ := buildTestCert(t)
	// Flip one byte of the attestation signature.
	sigBytes, _ := decodeHexString(cert.AttestSignature)
	sigBytes[0] ^= 0xff
	cert.AttestSignature = hex.EncodeToString(sigBytes)
	if err := verifyCertificate(cert); err == nil {
		t.Fatal("expected error for invalid attestation signature")
	}
}

func TestVerifyProof_Valid(t *testing.T) {
	cert, _ := buildTestCert(t)

	priv, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Re-create the cert using the same key the proof will sign with.
	pubRaw := rawPubkey(priv)
	addr, err := ethereumAddress(pubRaw)
	if err != nil {
		t.Fatal(err)
	}
	_, attestPriv, _ := ed25519.GenerateKey(rand.Reader)
	cert2 := cert
	cert2.WalletPubkeyUncompressed = "0x04" + hex.EncodeToString(pubRaw)
	cert2.WalletAddress = addr.Hex()
	// Re-sign after updating pubkey/address.
	pub2, attestPriv2, _ := ed25519.GenerateKey(rand.Reader)
	cert2.AttestPubkey = hex.EncodeToString([]byte(pub2))
	_ = attestPriv
	payload2, _ := encodeCertificatePayload(cert2)
	hash2 := sha256.Sum256(payload2)
	cert2.PayloadHashSHA256 = hex.EncodeToString(hash2[:])
	cert2.AttestSignature = hex.EncodeToString(ed25519.Sign(attestPriv2, hash2[:]))

	// Build proof.
	var challenge [32]byte
	if _, err = rand.Read(challenge[:]); err != nil {
		t.Fatal(err)
	}
	payloadHash, _ := decodeHex32(cert2.PayloadHashSHA256)
	msgHash := crypto.Keccak256([]byte(proofDomain), payloadHash[:], challenge[:])

	rawSig, err := crypto.Sign(msgHash, priv)
	if err != nil {
		t.Fatal(err)
	}
	ethSig, _, err := finalizeEthereumSignature(msgHash, pubRaw, rawSig[:64])
	if err != nil {
		t.Fatal(err)
	}

	p := proof{
		Schema:            proofSchema,
		Certificate:       cert2,
		Challenge:         hex.EncodeToString(challenge[:]),
		WalletMessageHash: hex.EncodeToString(msgHash),
		WalletSignature:   "0x" + hex.EncodeToString(ethSig),
	}
	if err = verifyProof(p); err != nil {
		t.Fatalf("verifyProof: %v", err)
	}
}

func TestNormalizeJSON(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`{"b":2,"a":1}`, `{"b":2,"a":1}`},
		{`{ "x" : 1 }`, `{"x":1}`},
	}
	for _, c := range cases {
		got, err := normalizeJSON([]byte(c.in))
		if err != nil {
			t.Errorf("normalizeJSON(%q): %v", c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("normalizeJSON(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	if _, err := normalizeJSON([]byte(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUDIRoundtrip(t *testing.T) {
	original := tkeyclient.UDI{
		VendorID:        0x1234,
		ProductID:       0x3f,
		ProductRevision: 0x0a,
		Serial:          0xcafebabe,
	}
	hexStr := udiHexBE(original)
	parsed, err := parseUDIHexBE(hexStr)
	if err != nil {
		t.Fatalf("parseUDIHexBE: %v", err)
	}
	if parsed.VendorID != original.VendorID ||
		parsed.ProductID != original.ProductID ||
		parsed.ProductRevision != original.ProductRevision ||
		parsed.Serial != original.Serial {
		t.Errorf("UDI roundtrip mismatch: got %+v, want %+v", *parsed, original)
	}
}

func TestParseUDIHexBE_Errors(t *testing.T) {
	if _, err := parseUDIHexBE("not-hex"); err == nil {
		t.Error("expected error for non-hex input")
	}
	if _, err := parseUDIHexBE("0x1234"); err == nil {
		t.Error("expected error for wrong length")
	}
}
