package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
)

func TestParseUint64(t *testing.T) {
	cases := []struct {
		in   any
		want uint64
		err  bool
	}{
		{float64(21000), 21000, false},
		{"0x15180", 0x15180, false},
		{"86400", 86400, false},
		{float64(-1), 0, true},
		{"not-a-number", 0, true},
	}
	for _, c := range cases {
		got, err := parseUint64(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseUint64(%v): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUint64(%v): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseUint64(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseBigInt(t *testing.T) {
	cases := []struct {
		in   any
		want string
		err  bool
	}{
		{float64(1e9), "1000000000", false},
		{"0x3b9aca00", "1000000000", false},
		{"1000000000", "1000000000", false},
		{"not-a-number", "", true},
	}
	for _, c := range cases {
		got, err := parseBigInt(c.in)
		if c.err {
			if err == nil {
				t.Errorf("parseBigInt(%v): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseBigInt(%v): %v", c.in, err)
			continue
		}
		want, _ := new(big.Int).SetString(c.want, 10)
		if got.Cmp(want) != 0 {
			t.Errorf("parseBigInt(%v) = %s, want %s", c.in, got, want)
		}
	}
}

func TestParseUnsignedTransaction_Legacy(t *testing.T) {
	raw := `{
		"nonce": 1,
		"gasPrice": "0x3b9aca00",
		"gas": 21000,
		"to": "0x000000000000000000000000000000000000dEaD",
		"value": "0xde0b6b3a7640000",
		"data": "0x"
	}`
	tx, signer, err := parseUnsignedTransaction([]byte(raw))
	if err != nil {
		t.Fatalf("parseUnsignedTransaction: %v", err)
	}
	if tx.Nonce() != 1 {
		t.Errorf("nonce: got %d, want 1", tx.Nonce())
	}
	if tx.Gas() != 21000 {
		t.Errorf("gas: got %d, want 21000", tx.Gas())
	}
	_ = signer.Hash(tx)
}

func TestParseUnsignedTransaction_EIP1559(t *testing.T) {
	raw := `{
		"type": "0x2",
		"chainId": "0x1",
		"nonce": 5,
		"maxPriorityFeePerGas": "0x3b9aca00",
		"maxFeePerGas": "0x77359400",
		"gas": 21000,
		"to": "0x000000000000000000000000000000000000dEaD",
		"value": "0x0",
		"data": "0x"
	}`
	tx, signer, err := parseUnsignedTransaction([]byte(raw))
	if err != nil {
		t.Fatalf("parseUnsignedTransaction: %v", err)
	}
	if tx.Type() != types.DynamicFeeTxType {
		t.Errorf("tx type: got %d, want %d", tx.Type(), types.DynamicFeeTxType)
	}
	_ = signer.Hash(tx)
}

func TestParseUnsignedTransaction_ContractCreation(t *testing.T) {
	raw := `{
		"type": "0x2",
		"chainId": "0x1",
		"nonce": 0,
		"maxPriorityFeePerGas": "0x3b9aca00",
		"maxFeePerGas": "0x77359400",
		"gas": 100000,
		"value": "0x0",
		"data": "0x6080604052"
	}`
	tx, _, err := parseUnsignedTransaction([]byte(raw))
	if err != nil {
		t.Fatalf("parseUnsignedTransaction: %v", err)
	}
	if tx.To() != nil {
		t.Errorf("expected nil To for contract creation, got %s", tx.To())
	}
}

func TestParseUnsignedTransaction_MissingRequired(t *testing.T) {
	cases := []string{
		`{"gasPrice":"0x1","to":"0xd3CdA913deB6f4967b2Ef3aa68f5A843838A0F6"}`,
		`{"gas":21000,"to":"0xd3CdA913deB6f4967b2Ef3aa68f5A843838A0F6"}`,
		`{"type":"0x2","chainId":"0x1","nonce":0,"maxFeePerGas":"0x1","gas":21000,"to":"0xd3CdA913deB6f4967b2Ef3aa68f5A843838A0F6"}`,
	}
	for _, c := range cases {
		if _, _, err := parseUnsignedTransaction([]byte(c)); err == nil {
			t.Errorf("expected error for: %s", c)
		}
	}
}

func TestReadMessageInput(t *testing.T) {
	got, err := readMessageInput("hello", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}

	got, err = readMessageInput("", "0x68656c6c6f", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}

	if _, err = readMessageInput("", "", ""); err == nil {
		t.Fatal("expected error for zero inputs")
	}
	if _, err = readMessageInput("a", "0x61", ""); err == nil {
		t.Fatal("expected error for two inputs")
	}
}
