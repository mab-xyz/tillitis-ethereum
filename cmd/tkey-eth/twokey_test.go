package main

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func buildTestBundle(t *testing.T) twoKeyBundle {
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

	fwHash := make([]byte, sha512.Size)
	for i := range fwHash {
		fwHash[i] = byte(i)
	}
	identityPub := make([]byte, 32)
	for i := range identityPub {
		identityPub[i] = byte(i + 64)
	}
	veriAppHash := make([]byte, sha512.Size)
	for i := range veriAppHash {
		veriAppHash[i] = byte(i + 1)
	}
	walletSHA256 := make([]byte, 32)
	walletB2s := make([]byte, 32)

	return twoKeyBundle{
		Schema:     twoKeySchema,
		Phase:      "wallet-signed",
		UDI:        "0102030405060708",
		VendorID:   0x0001,
		ProductID:  0x01,
		ProductRev: 0x00,
		TillitisIdentity: twoKeyTillitisIdentity{
			FirmwareSHA512:      hex.EncodeToString(fwHash),
			IdentityPubkey:      hex.EncodeToString(identityPub),
			VerificationAppHash: hex.EncodeToString(veriAppHash),
		},
		WalletApp: &twoKeyWalletApp{
			Name0:         "eth ",
			Name1:         "sign",
			Version:       1,
			DigestSHA256:  hex.EncodeToString(walletSHA256),
			DigestBLAKE2s: hex.EncodeToString(walletB2s),
		},
		WalletPubkeyUncompressed: "0x04" + hex.EncodeToString(pubRaw),
		WalletAddress:            addr.Hex(),
	}
}

func TestEncodeTwoKeyBindingPayload_Deterministic(t *testing.T) {
	bundle := buildTestBundle(t)

	p1, err := encodeTwoKeyBindingPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := encodeTwoKeyBindingPayload(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(p1) != hex.EncodeToString(p2) {
		t.Fatal("encodeTwoKeyBindingPayload is not deterministic")
	}
}

func TestTwoKeyBindingHash_Deterministic(t *testing.T) {
	bundle := buildTestBundle(t)

	h1, err := twoKeyBindingHash(bundle)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := twoKeyBindingHash(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("twoKeyBindingHash is not deterministic")
	}
}

func TestEncodeTwoKeyBindingPayload_MissingWalletApp(t *testing.T) {
	bundle := buildTestBundle(t)
	bundle.WalletApp = nil
	if _, err := encodeTwoKeyBindingPayload(bundle); err == nil {
		t.Fatal("expected error for nil WalletApp")
	}
}

func TestEncodeTwoKeyBindingPayload_WrongFirmwareHashLen(t *testing.T) {
	bundle := buildTestBundle(t)
	bundle.TillitisIdentity.FirmwareSHA512 = hex.EncodeToString([]byte{1, 2, 3})
	if _, err := encodeTwoKeyBindingPayload(bundle); err == nil {
		t.Fatal("expected error for wrong firmware hash length")
	}
}

func TestBuildTillitisVendorMessage(t *testing.T) {
	udi := "0102030405060708"
	fwHash := make([]byte, sha512.Size)
	pubKey := make([]byte, 32)

	msg, err := buildTillitisVendorMessage(udi, fwHash, pubKey)
	if err != nil {
		t.Fatalf("buildTillitisVendorMessage: %v", err)
	}
	want := 8 + sha512.Size + 32
	if len(msg) != want {
		t.Errorf("message length %d, want %d", len(msg), want)
	}

	if _, err = buildTillitisVendorMessage("not-hex", fwHash, pubKey); err == nil {
		t.Error("expected error for non-hex UDI")
	}
	if _, err = buildTillitisVendorMessage("0102", fwHash, pubKey); err == nil {
		t.Error("expected error for short UDI")
	}
	if _, err = buildTillitisVendorMessage(udi, []byte{1, 2, 3}, pubKey); err == nil {
		t.Error("expected error for short firmware hash")
	}
}
