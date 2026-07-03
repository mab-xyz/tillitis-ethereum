package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tillitis/tkeyclient"
)

const (
	certSchema       = "tkey-eth-wallet-attest-v1"
	proofSchema      = "tkey-eth-wallet-proof-v1"
	proofDomain      = "TKEY-ETH-PROOF-V1"
	selfAssertedMode = "self-asserted"
)

type walletAppInfo struct {
	Name0        string `json:"name0"`
	Name1        string `json:"name1"`
	Version      uint32 `json:"version"`
	DigestSHA256 string `json:"digest_sha256"`
}

type ussInfo struct {
	Mode string `json:"mode"`
}

type certificate struct {
	Schema                   string            `json:"schema"`
	AttestMode               string            `json:"attest_mode"`
	UDI                      string            `json:"udi"`
	VendorID                 uint16            `json:"vendor_id"`
	ProductID                uint8             `json:"product_id"`
	ProductRev               uint8             `json:"product_rev"`
	WalletApp                walletAppInfo     `json:"wallet_app"`
	WalletPubkeyUncompressed string            `json:"wallet_pubkey_uncompressed"`
	WalletAddress            string            `json:"wallet_address"`
	USS                      ussInfo           `json:"uss"`
	IssuedAt                 string            `json:"issued_at"`
	AttestKeyType            string            `json:"attest_key_type"`
	AttestPubkey             string            `json:"attest_pubkey"`
	PayloadHashSHA256        string            `json:"payload_hash_sha256"`
	AttestSignature          string            `json:"attest_signature"`
	TillitisEvidence         *tillitisEvidence `json:"tillitis_evidence,omitempty"`
}

type tillitisEvidence struct {
	VerificationURL    string          `json:"verification_url"`
	VerificationJSON   json.RawMessage `json:"verification_json"`
	VerificationSHA256 string          `json:"verification_sha256"`
	BindingClaim       string          `json:"binding_claim"`
	BindingLimitation  string          `json:"binding_limitation"`
}

type proof struct {
	Schema            string      `json:"schema"`
	Certificate       certificate `json:"certificate"`
	Challenge         string      `json:"challenge"`
	WalletMessageHash string      `json:"wallet_message_hash"`
	WalletSignature   string      `json:"wallet_signature"`
}

type preparedWallet struct {
	tk      *tkeyclient.TillitisKey
	signer  ethSigner
	udi     *tkeyclient.UDI
	pubkey  []byte
	appName *tkeyclient.NameVersion
}

func (p *preparedWallet) Close() error {
	if p.tk != nil {
		return p.tk.Close()
	}
	return nil
}

func runAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	var cfg commonFlags
	var outPath string
	var seedPath string
	var udiHex string
	var embedTillitisEvidence bool
	var selfAsserted bool
	addCommonFlags(fs, &cfg)
	fs.StringVar(&outPath, "out", "artifacts/cert.json", "Path to write certificate JSON")
	fs.StringVar(&seedPath, "self-assert-seed-file", defaultSelfAssertSeedPath(), "Path to 32-byte hex seed for self-asserted attestation key")
	fs.StringVar(&udiHex, "udi", "", "UDI as 16 hex chars, for attesting a wallet app that is already running")
	fs.BoolVar(&embedTillitisEvidence, "embed-tillitis-evidence", true, "Fetch and embed the public Tillitis verification file for this UDI")
	fs.BoolVar(&selfAsserted, "self-asserted", true, "Use a local self-asserted attestation key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !selfAsserted {
		return errors.New("only --self-asserted is implemented")
	}

	pw, err := prepareWallet(cfg, false)
	if err != nil {
		return err
	}
	defer pw.Close()

	if pw.udi == nil {
		if udiHex == "" {
			return errors.New("missing UDI; replug and start from firmware mode or pass --udi")
		}
		udi, err := parseUDIHexBE(udiHex)
		if err != nil {
			return err
		}
		pw.udi = udi
	}

	appDigest, err := fileSHA256Hex(cfg.appPath)
	if err != nil {
		return err
	}
	addr, err := ethereumAddress(pw.pubkey)
	if err != nil {
		return err
	}
	seed, pub, priv, err := loadOrCreateSelfAssertKey(seedPath)
	if err != nil {
		return err
	}
	_ = seed

	cert := certificate{
		Schema:                   certSchema,
		AttestMode:               selfAssertedMode,
		UDI:                      udiHexBE(*pw.udi),
		VendorID:                 pw.udi.VendorID,
		ProductID:                pw.udi.ProductID,
		ProductRev:               pw.udi.ProductRevision,
		WalletApp:                walletAppInfo{Name0: pw.appName.Name0, Name1: pw.appName.Name1, Version: pw.appName.Version, DigestSHA256: appDigest},
		WalletPubkeyUncompressed: "0x04" + hex.EncodeToString(pw.pubkey),
		WalletAddress:            addr.Hex(),
		USS:                      ussInfo{Mode: ussMode(cfg.ussFile)},
		IssuedAt:                 time.Now().UTC().Format(time.RFC3339),
		AttestKeyType:            "ed25519",
		AttestPubkey:             hex.EncodeToString(pub),
	}

	payload, err := encodeCertificatePayload(cert)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(payload)
	cert.PayloadHashSHA256 = hex.EncodeToString(payloadHash[:])
	cert.AttestSignature = hex.EncodeToString(ed25519.Sign(priv, payloadHash[:]))

	if embedTillitisEvidence {
		evidence, err := fetchTillitisEvidence(cert.UDI)
		if err != nil {
			return err
		}
		cert.TillitisEvidence = evidence
	}

	return writeJSON(outPath, cert)
}

func runProve(args []string) error {
	fs := flag.NewFlagSet("prove", flag.ContinueOnError)
	var cfg commonFlags
	var certPath, outPath, challengeHex string
	addCommonFlags(fs, &cfg)
	fs.StringVar(&certPath, "cert", "artifacts/cert.json", "Path to certificate JSON")
	fs.StringVar(&outPath, "out", "artifacts/proof.json", "Path to write proof JSON")
	fs.StringVar(&challengeHex, "challenge", "", "32-byte challenge as hex; if empty a random challenge is generated")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cert, err := readCertificate(certPath)
	if err != nil {
		return err
	}

	var challenge [32]byte
	if challengeHex == "" {
		if _, err := rand.Read(challenge[:]); err != nil {
			return err
		}
	} else {
		challenge, err = decodeHex32(challengeHex)
		if err != nil {
			return err
		}
	}

	pw, err := prepareWallet(cfg, false)
	if err != nil {
		return err
	}
	defer pw.Close()

	expectedAddr, err := ethereumAddress(pw.pubkey)
	if err != nil {
		return err
	}
	if expectedAddr.Hex() != cert.WalletAddress {
		return fmt.Errorf("live wallet address %s does not match certificate %s", expectedAddr.Hex(), cert.WalletAddress)
	}

	payloadHash, err := decodeHex32(cert.PayloadHashSHA256)
	if err != nil {
		return fmt.Errorf("certificate payload_hash_sha256: %w", err)
	}
	msgHash := crypto.Keccak256([]byte(proofDomain), payloadHash[:], challenge[:])
	rawSig, err := pw.signer.SignDigest(msgHash)
	if err != nil {
		return err
	}
	ethSig, _, err := finalizeEthereumSignature(msgHash, pw.pubkey, rawSig)
	if err != nil {
		return err
	}

	p := proof{
		Schema:            proofSchema,
		Certificate:       cert,
		Challenge:         hex.EncodeToString(challenge[:]),
		WalletMessageHash: hex.EncodeToString(msgHash),
		WalletSignature:   "0x" + hex.EncodeToString(ethSig),
	}
	return writeJSON(outPath, p)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var certPath, proofPath string
	fs.StringVar(&certPath, "cert", "artifacts/cert.json", "Path to certificate JSON")
	fs.StringVar(&proofPath, "proof", "", "Optional path to proof JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cert, err := readCertificate(certPath)
	if err != nil {
		return err
	}
	if err := verifyCertificate(cert); err != nil {
		return err
	}
	fmt.Println("certificate: ok")

	if proofPath == "" {
		return nil
	}

	p, err := readProof(proofPath)
	if err != nil {
		return err
	}
	if err := verifyProof(p); err != nil {
		return err
	}
	fmt.Println("proof: ok")
	return nil
}

func prepareWallet(cfg commonFlags, requireUDI bool) (*preparedWallet, error) {
	if !cfg.verbose {
		tkeyclient.SilenceLogging()
	}

	port := cfg.port
	if port == "" {
		var err error
		port, err = tkeyclient.DetectSerialPort(false)
		if err != nil {
			return nil, err
		}
	}

	app, err := os.ReadFile(cfg.appPath)
	if err != nil {
		return nil, err
	}
	var uss []byte
	if cfg.ussFile != "" {
		uss, err = os.ReadFile(cfg.ussFile)
		if err != nil {
			return nil, err
		}
	}

	tk := tkeyclient.New()
	if err := tk.Connect(port); err != nil {
		return nil, err
	}

	pw := &preparedWallet{tk: tk, signer: newEthSigner(tk)}

	nameVer, err := tk.GetNameVersion()
	if err == nil && nameVer.Name0 == "tk1 " && nameVer.Name1 == "mkdf" {
		udi, err := tk.GetUDI()
		if err != nil {
			pw.Close()
			return nil, err
		}
		pw.udi = udi
		if err := tk.LoadApp(app, uss); err != nil {
			pw.Close()
			return nil, err
		}
	} else {
		if requireUDI {
			pw.Close()
			return nil, errors.New("attest requires a fresh firmware-mode device; replug and retry")
		}
		if len(uss) != 0 {
			pw.Close()
			return nil, errors.New("app already running; replug to apply --uss-file")
		}
	}

	appName, err := pw.signer.GetAppNameVersion()
	if err != nil {
		pw.Close()
		return nil, err
	}
	if appName.Name0 != "eth " || appName.Name1 != "sign" {
		pw.Close()
		return nil, fmt.Errorf("unexpected app running: %q/%q", appName.Name0, appName.Name1)
	}
	pubkey, err := pw.signer.GetPubkey()
	if err != nil {
		pw.Close()
		return nil, err
	}
	pw.appName = appName
	pw.pubkey = pubkey
	return pw, nil
}

func ussMode(path string) string {
	if path == "" {
		return "none"
	}
	return "present"
}

func fileSHA256Hex(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func loadOrCreateSelfAssertKey(path string) ([]byte, ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, nil, err
	}
	if b, err := os.ReadFile(path); err == nil {
		seedBytes, err := decodeHexString(string(bytesTrimSpace(b)))
		if err != nil {
			return nil, nil, nil, err
		}
		if len(seedBytes) != ed25519.SeedSize {
			return nil, nil, nil, fmt.Errorf("seed file must contain %d bytes", ed25519.SeedSize)
		}
		priv := ed25519.NewKeyFromSeed(seedBytes)
		return seedBytes, priv.Public().(ed25519.PublicKey), priv, nil
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return seed, priv.Public().(ed25519.PublicKey), priv, nil
}

func encodeCertificatePayload(cert certificate) ([]byte, error) {
	pubkey, err := decodeHexString(cert.WalletPubkeyUncompressed)
	if err != nil {
		return nil, err
	}
	if len(pubkey) != 65 || pubkey[0] != 0x04 {
		return nil, errors.New("wallet pubkey must be uncompressed 65-byte secp256k1 key")
	}
	addrBytes := common.HexToAddress(cert.WalletAddress).Bytes()
	if len(addrBytes) != 20 {
		return nil, errors.New("wallet address must be 20 bytes")
	}
	appDigest, err := decodeHexString(cert.WalletApp.DigestSHA256)
	if err != nil {
		return nil, err
	}
	if len(appDigest) != 32 {
		return nil, errors.New("wallet app digest must be 32 bytes")
	}

	buf := make([]byte, 0, 8+8+2+1+1+4+4+4+32+65+20+1+15)
	buf = append(buf, []byte("TKEYETH1")...)
	buf = append(buf, udiHexToBEBytes(cert.UDI)...)
	tmp2 := make([]byte, 2)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp2, cert.VendorID)
	buf = append(buf, tmp2...)
	buf = append(buf, cert.ProductID, cert.ProductRev)
	buf = appendFixed4(buf, cert.WalletApp.Name0)
	buf = appendFixed4(buf, cert.WalletApp.Name1)
	binary.BigEndian.PutUint32(tmp4, cert.WalletApp.Version)
	buf = append(buf, tmp4...)
	buf = append(buf, appDigest...)
	buf = append(buf, pubkey...)
	buf = append(buf, addrBytes...)
	if cert.USS.Mode == "present" {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	buf = append(buf, make([]byte, 15)...)
	return buf, nil
}

func verifyCertificate(cert certificate) error {
	if cert.Schema != certSchema {
		return fmt.Errorf("unexpected certificate schema %q", cert.Schema)
	}
	payload, err := encodeCertificatePayload(cert)
	if err != nil {
		return err
	}
	payloadHash := sha256.Sum256(payload)
	if cert.PayloadHashSHA256 != hex.EncodeToString(payloadHash[:]) {
		return errors.New("payload hash mismatch")
	}
	pubkeyBytes, err := decodeHexString(cert.AttestPubkey)
	if err != nil {
		return err
	}
	sigBytes, err := decodeHexString(cert.AttestSignature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkeyBytes), payloadHash[:], sigBytes) {
		return errors.New("attestation signature invalid")
	}
	walletPubkey, err := decodeHexString(cert.WalletPubkeyUncompressed)
	if err != nil {
		return err
	}
	addr, err := ethereumAddress(walletPubkey[1:])
	if err != nil {
		return err
	}
	if addr.Hex() != cert.WalletAddress {
		return errors.New("wallet address does not match wallet pubkey")
	}
	if cert.TillitisEvidence != nil {
		if err := verifyTillitisEvidence(*cert.TillitisEvidence, cert.UDI); err != nil {
			return err
		}
	}
	return nil
}

func verifyProof(p proof) error {
	if p.Schema != proofSchema {
		return fmt.Errorf("unexpected proof schema %q", p.Schema)
	}
	if err := verifyCertificate(p.Certificate); err != nil {
		return err
	}
	challenge, err := decodeHex32(p.Challenge)
	if err != nil {
		return err
	}
	payloadHash, err := decodeHex32(p.Certificate.PayloadHashSHA256)
	if err != nil {
		return err
	}
	wantHash := crypto.Keccak256([]byte(proofDomain), payloadHash[:], challenge[:])
	if p.WalletMessageHash != hex.EncodeToString(wantHash) {
		return errors.New("wallet message hash mismatch")
	}
	sig, err := decodeHexString(p.WalletSignature)
	if err != nil {
		return err
	}
	recovered, err := crypto.SigToPub(wantHash, sig)
	if err != nil {
		return err
	}
	recoveredRaw := crypto.FromECDSAPub(recovered)
	certPubkey, err := decodeHexString(p.Certificate.WalletPubkeyUncompressed)
	if err != nil {
		return err
	}
	if len(recoveredRaw) != 65 || len(certPubkey) != 65 || string(recoveredRaw) != string(certPubkey) {
		return errors.New("wallet signature does not recover certificate pubkey")
	}
	return nil
}

func readCertificate(path string) (certificate, error) {
	var cert certificate
	b, err := os.ReadFile(path)
	if err != nil {
		return cert, err
	}
	err = json.Unmarshal(b, &cert)
	return cert, err
}

func readProof(path string) (proof, error) {
	var p proof
	b, err := os.ReadFile(path)
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(b, &p)
	return p, err
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func fetchTillitisEvidence(udiHex string) (*tillitisEvidence, error) {
	url := "https://tkey.tillitis.se/verify/" + udiHex
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url) // #nosec G107
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching Tillitis verification file: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeJSON(body)
	if err != nil {
		return nil, fmt.Errorf("normalizing Tillitis verification JSON: %w", err)
	}
	sum := sha256.Sum256(normalized)
	return &tillitisEvidence{
		VerificationURL:    url,
		VerificationJSON:   append([]byte{}, body...),
		VerificationSHA256: hex.EncodeToString(sum[:]),
		BindingClaim:       "This embedded verification file is public Tillitis evidence that the UDI corresponds to a genuine Tillitis-backed device identity under the Tillitis verification process.",
		BindingLimitation:  "This does not by itself prove that the Ethereum wallet pubkey in this certificate is vendor-attested or non-exportable; it is adjacent genuine-device evidence only.",
	}, nil
}

func verifyTillitisEvidence(e tillitisEvidence, expectedUDI string) error {
	if e.VerificationURL != "https://tkey.tillitis.se/verify/"+expectedUDI {
		return errors.New("Tillitis verification URL does not match certificate UDI")
	}
	normalized, err := normalizeJSON(e.VerificationJSON)
	if err != nil {
		return fmt.Errorf("Tillitis verification JSON invalid: %w", err)
	}
	sum := sha256.Sum256(normalized)
	if e.VerificationSHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("Tillitis verification SHA-256 mismatch")
	}
	var parsed struct {
		Timestamp string `json:"timestamp"`
		AppTag    string `json:"apptag"`
		AppHash   string `json:"apphash"`
		Proof     string `json:"proof"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(e.VerificationJSON, &parsed); err != nil {
		return fmt.Errorf("Tillitis verification JSON invalid: %w", err)
	}
	if parsed.Timestamp == "" || parsed.AppTag == "" || parsed.AppHash == "" {
		return errors.New("Tillitis verification JSON missing required fields")
	}
	if parsed.Proof == "" && parsed.Signature == "" {
		return errors.New("Tillitis verification JSON missing proof/signature")
	}
	return nil
}

func normalizeJSON(b []byte) ([]byte, error) {
	var dst bytes.Buffer
	if err := json.Compact(&dst, b); err != nil {
		return nil, err
	}
	return dst.Bytes(), nil
}

func udiHexBE(u tkeyclient.UDI) string {
	return hex.EncodeToString(udiBytesBE(u))
}

func udiBytesBE(u tkeyclient.UDI) []byte {
	vpr := (uint32(u.Unnamed) << 28) | (uint32(u.VendorID) << 12) | (uint32(u.ProductID) << 6) | uint32(u.ProductRevision)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[:4], vpr)
	binary.BigEndian.PutUint32(buf[4:], u.Serial)
	return buf
}

func udiHexToBEBytes(s string) []byte {
	b, _ := decodeHexString(s)
	return b
}

func parseUDIHexBE(s string) (*tkeyclient.UDI, error) {
	b, err := decodeHexString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("UDI must be 8 bytes, got %d", len(b))
	}
	vpr := binary.BigEndian.Uint32(b[:4])
	serial := binary.BigEndian.Uint32(b[4:])
	u := &tkeyclient.UDI{
		Unnamed:         uint8((vpr >> 28) & 0xf),
		VendorID:        uint16((vpr >> 12) & 0xffff),
		ProductID:       uint8((vpr >> 6) & 0x3f),
		ProductRevision: uint8(vpr & 0x3f),
		Serial:          serial,
	}
	return u, nil
}

func appendFixed4(dst []byte, s string) []byte {
	b := []byte(s)
	if len(b) < 4 {
		tmp := make([]byte, 4)
		copy(tmp, b)
		return append(dst, tmp...)
	}
	return append(dst, b[:4]...)
}

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\t' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\t' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}
