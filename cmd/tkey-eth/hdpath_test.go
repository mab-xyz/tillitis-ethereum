package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestParseHDPath(t *testing.T) {
	ok := map[string][]uint32{
		"m":                      {},
		"m/0":                    {0},
		"m/44'/60'/0'/0/0":       {44 | hardened, 60 | hardened, hardened, 0, 0},
		"m/44h/60H/0'/0/7":       {44 | hardened, 60 | hardened, hardened, 0, 7},
		"m/2147483647'":          {0xffffffff},
		"m/2147483647":           {0x7fffffff},
		"m/1/2/3/4/5/6/7/8/9/10": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
	}
	for in, want := range ok {
		got, err := parseHDPath(in)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("parseHDPath(%q) = %v, %v; want %v", in, got, err, want)
		}
		if err == nil && formatHDPath(got) != strings.ReplaceAll(strings.ReplaceAll(in, "h", "'"), "H", "'") {
			t.Errorf("formatHDPath(parseHDPath(%q)) = %q", in, formatHDPath(got))
		}
	}
	for _, in := range []string{"", "44'/60'", "m/", "m//1", "m/2147483648", "m/-1", "m/+1", "m/x", "m/1''", "m/1/2/3/4/5/6/7/8/9/10/11", "M/0"} {
		if got, err := parseHDPath(in); err == nil {
			t.Errorf("parseHDPath(%q) = %v; want error", in, got)
		}
	}
}

func TestEncodeHDPath(t *testing.T) {
	got := encodeHDPath([]uint32{44 | hardened, 1})
	want := []byte{2, 0x80, 0, 0, 44, 0, 0, 0, 1}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeHDPath = %x; want %x", got, want)
	}
	if n := len(encodeHDPath(make([]uint32, maxHDDepth))) + 32; n > 127 {
		t.Fatalf("max sign payload %d bytes exceeds 127-byte frame", n)
	}
}

// Every non-hardened step in the BIP-32 spec vectors: CKDpub(parent) == pub(child private key).
func TestCKDPubAgainstSpecVectors(t *testing.T) {
	f, err := os.Open("../../tests/bip32/vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	type node struct{ pub, cc []byte }
	nodes := map[string]node{}
	checked := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		seed, path := fields[0], fields[1]
		cc, _ := hex.DecodeString(fields[2])
		keyBytes, _ := hex.DecodeString(fields[3])
		key, err := crypto.ToECDSA(keyBytes)
		if err != nil {
			t.Fatal(err)
		}
		pub := crypto.FromECDSAPub(&key.PublicKey)[1:]
		nodes[seed+" "+path] = node{pub, cc}

		i := strings.LastIndex(path, "/")
		if i < 0 || strings.HasSuffix(path, "'") {
			continue
		}
		parent, ok := nodes[seed+" "+path[:i]]
		if !ok {
			t.Fatalf("parent of %s missing", path)
		}
		idx, err := parseHDPath("m" + path[i:])
		if err != nil {
			t.Fatal(err)
		}
		gotPub, gotCC, err := ckdPub(parent.pub, parent.cc, idx[0])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotPub, pub) || !bytes.Equal(gotCC, cc) {
			t.Errorf("ckdPub mismatch at %s", path)
		}
		checked++
	}
	if checked < 5 {
		t.Fatalf("only %d non-hardened steps checked", checked)
	}
	if _, _, err := ckdPub(nodes["000102030405060708090a0b0c0d0e0f m"].pub, nodes["000102030405060708090a0b0c0d0e0f m"].cc, hardened); err == nil {
		t.Error("ckdPub accepted a hardened index")
	}
}

func TestCheckDeviceSignatureAcceptsHighS(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _ := crypto.GenerateKey()
	pub := crypto.FromECDSAPub(&key.PublicKey)[1:]
	digest := crypto.Keccak256([]byte("verify-hd"))
	sig, err := crypto.Sign(digest, key)
	if err != nil {
		t.Fatal(err)
	}
	low := sig[:64]
	high := append([]byte{}, low...)
	s := new(big.Int).SetBytes(high[32:])
	new(big.Int).Sub(crypto.S256().Params().N, s).FillBytes(high[32:])

	if crypto.VerifySignature(append([]byte{0x04}, pub...), digest, high) {
		t.Fatal("precondition: VerifySignature was expected to reject high-S")
	}
	for name, raw := range map[string][]byte{"low-S": low, "high-S": high} {
		if err := checkDeviceSignature(digest, pub, raw); err != nil {
			t.Errorf("%s rejected: %v", name, err)
		}
	}
	if err := checkDeviceSignature(digest, crypto.FromECDSAPub(&other.PublicKey)[1:], low); err == nil {
		t.Error("signature accepted under the wrong pubkey")
	}
}
