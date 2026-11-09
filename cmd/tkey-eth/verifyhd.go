package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
)

// runVerifyHD cross-checks the HD app against an independent host implementation:
// for children 0..count-1 of --path, the device's pubkey and chain code must equal
// CKDpub of the device's parent (pubkey, chain code), and a device signature at
// each child must recover to that child's key. Silent on success.
func runVerifyHD(args []string) error {
	fs := flag.NewFlagSet("verify-hd", flag.ContinueOnError)
	var cfg commonFlags
	var count int
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.IntVar(&count, "count", 3, "Number of non-hardened children of --path to check")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.hdPath == "" {
		cfg.hdPath = "m/44'/60'/0'/0"
	}
	base, err := parseHDPath(cfg.hdPath)
	if err != nil {
		return err
	}
	if len(base)+1 > maxHDDepth {
		return fmt.Errorf("--path too deep to add a child")
	}

	_, err = withSigner(cfg, func(s *ethSigner) (struct{}, error) {
		parentPub, parentCC, err := s.GetPubkeyChain(base)
		if err != nil {
			return struct{}{}, err
		}
		for i := uint32(0); i < uint32(count); i++ {
			child := append(append([]uint32{}, base...), i)
			name := formatHDPath(child)
			wantPub, wantCC, err := ckdPub(parentPub, parentCC, i)
			if err != nil {
				return struct{}{}, fmt.Errorf("%s: %w", name, err)
			}
			gotPub, gotCC, err := s.GetPubkeyChain(child)
			if err != nil {
				return struct{}{}, err
			}
			if !bytes.Equal(gotPub, wantPub) || !bytes.Equal(gotCC, wantCC) {
				return struct{}{}, fmt.Errorf("%s: device key differs from host CKDpub", name)
			}

			var digest [32]byte
			if _, err := rand.Read(digest[:]); err != nil {
				return struct{}{}, err
			}
			cs := *s
			cs.path = child
			sig, err := cs.SignDigest(digest[:])
			if err != nil {
				return struct{}{}, fmt.Errorf("%s: %w", name, err)
			}
			if err := checkDeviceSignature(digest[:], gotPub, sig); err != nil {
				return struct{}{}, fmt.Errorf("%s: %w", name, err)
			}
		}
		return struct{}{}, nil
	})
	return err
}

// checkDeviceSignature accepts a raw device signature (either S half, as uECC
// returns it) iff it recovers to pub64 after the CLI's own low-S normalization.
// crypto.VerifySignature alone is wrong here: it rejects high-S signatures.
func checkDeviceSignature(digest, pub64, rawSig []byte) error {
	if _, _, err := finalizeEthereumSignature(digest, pub64, rawSig); err != nil {
		return fmt.Errorf("signature does not recover to its pubkey: %w", err)
	}
	return nil
}
