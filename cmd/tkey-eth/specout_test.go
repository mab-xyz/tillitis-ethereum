package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var update = flag.Bool("update", false, "rewrite testdata/golden")

// A fixed key stands in for the TKey: crypto.Sign is deterministic (RFC 6979) and low-s.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func softSigner(t *testing.T, highS bool) digestSigner {
	key := testKey(t)
	return func(digest []byte) ([]byte, []byte, error) {
		sig, err := crypto.Sign(digest, key)
		if err != nil {
			return nil, nil, err
		}
		raw := sig[:64]
		if highS { // the device may return either half; finalizeEthereumSignature must fix it
			n := crypto.S256().Params().N
			s := new(big.Int).Sub(n, new(big.Int).SetBytes(raw[32:]))
			s.FillBytes(raw[32:])
		}
		return rawPubkey(key), raw, nil
	}
}

func readTypedData(t *testing.T) apitypes.TypedData {
	t.Helper()
	body, err := os.ReadFile("testdata/ether-mail.json")
	if err != nil {
		t.Fatal(err)
	}
	var td apitypes.TypedData
	if err := json.Unmarshal(body, &td); err != nil {
		t.Fatal(err)
	}
	return td
}

func testTx() (*types.Transaction, types.Signer) {
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: big.NewInt(1), GasTipCap: big.NewInt(1_000_000_000), GasFeeCap: big.NewInt(2_000_000_000),
		Gas: 21000, To: &to, Value: big.NewInt(1),
	})
	return tx, types.LatestSignerForChainID(big.NewInt(1))
}

// The formats of hw-wallet-cli-spec, repeated here so a Go-only run still checks them.
var (
	reSig    = regexp.MustCompile(`^0x[0-9a-f]{128}1[bc]$`)
	reDigest = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
)

// recovers checks that signature (v = 27/28) over digest comes from the test key.
func recovers(t *testing.T, digest, signature string) {
	t.Helper()
	if !reSig.MatchString(signature) {
		t.Fatalf("signature %q does not match the spec format", signature)
	}
	sig, _ := hexutil.Decode(signature)
	sig[64] -= 27
	d, _ := hexutil.Decode(digest)
	pub, err := crypto.SigToPub(d, sig)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := crypto.PubkeyToAddress(*pub), crypto.PubkeyToAddress(testKey(t).PublicKey); got != want {
		t.Fatalf("recovered %s, want %s", got, want)
	}
}

func TestSignature27(t *testing.T) {
	sig := make([]byte, 65)
	for v, want := range map[byte]string{0: "1b", 1: "1c"} {
		sig[64] = v
		got, err := signature27(sig)
		if err != nil || !strings.HasSuffix(got, want) {
			t.Errorf("v=%d: got %q, %v; want suffix %s", v, got, err, want)
		}
	}
	sig[64] = 27 // already converted: refuse to convert twice
	if _, err := signature27(sig); err == nil {
		t.Error("v=27 accepted")
	}
	if _, err := signature27(sig[:64]); err == nil {
		t.Error("64-byte signature accepted")
	}
}

func TestDigestOutput(t *testing.T) {
	for _, highS := range []bool{false, true} {
		digest := crypto.Keccak256([]byte("digest"))
		out, err := makeDigestOutput(softSigner(t, highS), digest)
		if err != nil {
			t.Fatal(err)
		}
		recovers(t, out.Digest, out.Signature)
		if out.Digest != hexutil.Encode(digest) || out.Address != crypto.PubkeyToAddress(testKey(t).PublicKey).Hex() {
			t.Errorf("highS=%v: bad digest or address in %+v", highS, out)
		}
	}
}

func TestDigestOutputRejectsWrongKey(t *testing.T) {
	other, _ := crypto.GenerateKey()
	signer := func(digest []byte) ([]byte, []byte, error) { // pubkey of one key, signature of another
		sig, err := crypto.Sign(digest, other)
		return rawPubkey(testKey(t)), sig[:64], err
	}
	if _, err := makeDigestOutput(signer, make([]byte, 32)); err == nil {
		t.Fatal("a signature from another key was accepted")
	}
}

func TestPersonalOutput(t *testing.T) {
	out, err := makePersonalOutput(softSigner(t, false), []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := accounts.TextAndHash([]byte("hi"))
	if out.Digest != hexutil.Encode(want) {
		t.Errorf("digest %s, want %s", out.Digest, hexutil.Encode(want))
	}
	recovers(t, out.Digest, out.Signature)
}

// The Ether Mail example of EIP-712 itself: an independent reference for the digest.
func TestTypedOutputMatchesEIP712Reference(t *testing.T) {
	out, err := makeTypedOutput(softSigner(t, false), readTypedData(t))
	if err != nil {
		t.Fatal(err)
	}
	if out.Digest != "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2" {
		t.Errorf("digest %s", out.Digest)
	}
	if !strings.HasPrefix(out.Encoded, "0x1901") || len(out.Encoded) != 2+2*66 {
		t.Errorf("encoded %q is not 0x1901 || domainSeparator || hashStruct", out.Encoded)
	}
	raw, _ := hexutil.Decode(out.Encoded)
	if hexutil.Encode(crypto.Keccak256(raw)) != out.Digest {
		t.Error("digest is not keccak(encoded)")
	}
	recovers(t, out.Digest, out.Signature)
}

func TestTxOutput(t *testing.T) {
	tx, signer := testTx()
	out, err := makeTxOutput(softSigner(t, true), tx, signer)
	if err != nil {
		t.Fatal(err)
	}
	recovers(t, out.Digest, out.Signature)
	raw, _ := hexutil.Decode(out.RawTransaction)
	var signed types.Transaction
	if err := signed.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	sender, err := types.Sender(signer, &signed)
	if err != nil || sender.Hex() != out.Address {
		t.Errorf("sender %v (%v), want %s", sender, err, out.Address)
	}
	if signed.Hash().Hex() != out.TxHash {
		t.Errorf("tx_hash %s, want %s", out.TxHash, signed.Hash().Hex())
	}
	v, _, _ := signed.RawSignatureValues() // typed transactions carry yParity, the signature field 27/28
	if v.Sign() < 0 || v.Cmp(big.NewInt(1)) > 0 {
		t.Errorf("transaction yParity %v", v)
	}
}

func TestAddressOutput(t *testing.T) {
	out, err := makeAddressOutput(rawPubkey(testKey(t)))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^0x[0-9a-f]{128}$`).MatchString(out.Pubkey) {
		t.Errorf("pubkey %q is not 0x + X||Y", out.Pubkey)
	}
}

// Golden JSON, one file per command, checked by `hw-wallet-cli-check --golden testdata/golden`.
func TestGolden(t *testing.T) {
	sign := softSigner(t, false)
	digest, err := makeDigestOutput(sign, crypto.Keccak256([]byte("digest")))
	if err != nil {
		t.Fatal(err)
	}
	personal, _ := makePersonalOutput(sign, []byte("hi"))
	typed, _ := makeTypedOutput(sign, readTypedData(t))
	tx, signer := testTx()
	txOut, _ := makeTxOutput(sign, tx, signer)
	addr, _ := makeAddressOutput(rawPubkey(testKey(t)))
	cert := certificate{WalletAddress: addr.Address}
	golden := map[string]any{
		"address": addr, "sign-digest": digest, "sign-personal": personal, "sign-typed-data": typed,
		"sign-tx": txOut, "attest": makeAttestOutput(cert, "artifacts/cert.json"),
		"verify": makeVerifyOutput(cert, true),
	}
	for name, v := range golden {
		want, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, '\n')
		path := filepath.Join("testdata", "golden", name+".json")
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test -update ./cmd/tkey-eth/)", err)
		}
		if string(got) != string(want) {
			t.Errorf("%s drifted from the output; run go test -update and review the diff\n got: %s\nwant: %s", name, got, want)
		}
	}
}
