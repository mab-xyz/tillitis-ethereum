package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/blake2s"
)

const liveVerifySchema = "tkey-eth-live-verify-v1"
const liveVerifyDomain = "TKEY-ETH-LIVE-VERIFY-V1"

type liveVerifyBundle struct {
	Schema                   string            `json:"schema"`
	VerifiedAt               string            `json:"verified_at"`
	Claim                    string            `json:"claim"`
	Limitation               string            `json:"limitation"`
	UDI                      string            `json:"udi"`
	VendorID                 uint16            `json:"vendor_id"`
	ProductID                uint8             `json:"product_id"`
	ProductRev               uint8             `json:"product_rev"`
	WalletApp                liveWalletAppInfo `json:"wallet_app"`
	WalletPubkeyUncompressed string            `json:"wallet_pubkey_uncompressed"`
	WalletAddress            string            `json:"wallet_address"`
	Challenge                string            `json:"challenge"`
	WalletMessageHash        string            `json:"wallet_message_hash"`
	WalletSignature          string            `json:"wallet_signature"`
	TillitisEvidence         tillitisEvidence  `json:"tillitis_evidence"`
}

type liveWalletAppInfo struct {
	Name0               string `json:"name0"`
	Name1               string `json:"name1"`
	Version             uint32 `json:"version"`
	LoadedFrom          string `json:"loaded_from"`
	DigestBLAKE2sHost   string `json:"digest_blake2s_host"`
	DigestBLAKE2sDevice string `json:"digest_blake2s_device"`
}

func runVerifyLive(args []string) error {
	fs := flag.NewFlagSet("verify-live", flag.ContinueOnError)
	var cfg commonFlags
	var outPath string
	addCommonFlags(fs, &cfg)
	fs.StringVar(&outPath, "out", "artifacts/live-verify.json", "Path to write verifier transcript JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pw, err := prepareWallet(cfg, true)
	if err != nil {
		return err
	}
	defer pw.Close()
	if pw.udi == nil {
		return errors.New("expected UDI from firmware mode")
	}

	hostDigest, err := fileBLAKE2sHex(cfg.appPath)
	if err != nil {
		return err
	}
	deviceDigest, err := pw.signer.GetAppDigest()
	if err != nil {
		return err
	}
	deviceDigestHex := hex.EncodeToString(deviceDigest)
	if deviceDigestHex != hostDigest {
		return fmt.Errorf("device app digest %s does not match loaded app digest %s", deviceDigestHex, hostDigest)
	}

	addr, err := ethereumAddress(pw.pubkey)
	if err != nil {
		return err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	msgHash := crypto.Keccak256(
		[]byte(liveVerifyDomain),
		udiBytesBE(*pw.udi),
		deviceDigest,
		challenge,
	)
	rawSig, err := pw.signer.SignDigest(msgHash)
	if err != nil {
		return err
	}
	ethSig, recoveredAddr, err := finalizeEthereumSignature(msgHash, pw.pubkey, rawSig)
	if err != nil {
		return err
	}
	if recoveredAddr != addr {
		return fmt.Errorf("recovered address %s does not match wallet address %s", recoveredAddr.Hex(), addr.Hex())
	}
	if err := verifyRecoveredSignature(msgHash, ethSig, addr); err != nil {
		return err
	}

	evidence, err := fetchTillitisEvidence(udiHexBE(*pw.udi))
	if err != nil {
		return err
	}
	if err := verifyTillitisEvidence(*evidence, udiHexBE(*pw.udi)); err != nil {
		return err
	}

	bundle := liveVerifyBundle{
		Schema:     liveVerifySchema,
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
		Claim:      "This verifier observed a genuine Tillitis identity for the stated UDI, loaded the named wallet app binary, confirmed its BLAKE2s app digest on-device, and observed fresh wallet-key liveness for the stated Ethereum address.",
		Limitation: "This transcript is a verifier-witnessed live proof, not a portable vendor-signed certificate over the Ethereum wallet pubkey. It does not by itself prove non-exportability.",
		UDI:        udiHexBE(*pw.udi),
		VendorID:   pw.udi.VendorID,
		ProductID:  pw.udi.ProductID,
		ProductRev: pw.udi.ProductRevision,
		WalletApp: liveWalletAppInfo{
			Name0:               pw.appName.Name0,
			Name1:               pw.appName.Name1,
			Version:             pw.appName.Version,
			LoadedFrom:          filepath.Clean(cfg.appPath),
			DigestBLAKE2sHost:   hostDigest,
			DigestBLAKE2sDevice: deviceDigestHex,
		},
		WalletPubkeyUncompressed: "0x04" + hex.EncodeToString(pw.pubkey),
		WalletAddress:            addr.Hex(),
		Challenge:                hexutil.Encode(challenge),
		WalletMessageHash:        hexutil.Encode(msgHash),
		WalletSignature:          hexutil.Encode(ethSig),
		TillitisEvidence:         *evidence,
	}
	return writeJSON(outPath, bundle)
}

func fileBLAKE2sHex(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := blake2s.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
