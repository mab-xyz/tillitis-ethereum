package main

// BIP-32 path parsing, wire encoding for device/ethsign-hd, and host-side
// public child derivation (CKDpub) used to cross-check the device.

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

const (
	hardened    = uint32(0x80000000)
	maxHDDepth  = 10
	hdAppName1  = "hd32"
	legacyName1 = "sign"
)

func defaultHDAppPath() string {
	return filepath.Join("device", "ethsign-hd", "app.bin")
}

// parseHDPath parses "m/44'/60'/0'/0/0". Hardened markers: ' h H.
func parseHDPath(s string) ([]uint32, error) {
	parts := strings.Split(strings.TrimSpace(s), "/")
	if parts[0] != "m" {
		return nil, fmt.Errorf("path %q must start with m", s)
	}
	parts = parts[1:]
	if len(parts) > maxHDDepth {
		return nil, fmt.Errorf("path %q deeper than %d", s, maxHDDepth)
	}
	path := make([]uint32, 0, len(parts))
	for _, p := range parts {
		h := uint32(0)
		if n := len(p); n > 0 && (p[n-1] == '\'' || p[n-1] == 'h' || p[n-1] == 'H') {
			h, p = hardened, p[:n-1]
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil || p == "" || p[0] == '+' || uint32(v) >= hardened {
			return nil, fmt.Errorf("path %q: bad index %q", s, p)
		}
		path = append(path, uint32(v)|h)
	}
	return path, nil
}

func formatHDPath(path []uint32) string {
	var b strings.Builder
	b.WriteString("m")
	for _, i := range path {
		if i&hardened != 0 {
			fmt.Fprintf(&b, "/%d'", i&^hardened)
		} else {
			fmt.Fprintf(&b, "/%d", i)
		}
	}
	return b.String()
}

// encodeHDPath writes depth || u32 BE indices, as device/ethsign-hd/main.c expects.
func encodeHDPath(path []uint32) []byte {
	out := make([]byte, 1+4*len(path))
	out[0] = byte(len(path))
	for i, idx := range path {
		binary.BigEndian.PutUint32(out[1+4*i:], idx)
	}
	return out
}

// ckdPub derives a non-hardened child public key (64-byte X||Y) and chain code.
func ckdPub(pub64 []byte, chaincode []byte, index uint32) ([]byte, []byte, error) {
	if index&hardened != 0 {
		return nil, nil, errors.New("ckdPub: hardened index")
	}
	parent, err := crypto.UnmarshalPubkey(append([]byte{0x04}, pub64...))
	if err != nil {
		return nil, nil, err
	}
	mac := hmac.New(sha512.New, chaincode)
	mac.Write(crypto.CompressPubkey(parent))
	_ = binary.Write(mac, binary.BigEndian, index)
	I := mac.Sum(nil)
	il := new(big.Int).SetBytes(I[:32])
	curve := crypto.S256()
	if il.Cmp(curve.Params().N) >= 0 {
		return nil, nil, errors.New("ckdPub: invalid child (IL >= n)")
	}
	x, y := curve.ScalarBaseMult(I[:32])
	x, y = curve.Add(x, y, parent.X, parent.Y)
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, nil, errors.New("ckdPub: invalid child (point at infinity)")
	}
	out := make([]byte, 64)
	x.FillBytes(out[:32])
	y.FillBytes(out[32:])
	return out, I[32:], nil
}
