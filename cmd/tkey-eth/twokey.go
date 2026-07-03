package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tillitis/tkeyclient"
	"github.com/tillitis/tkeysign"
)

const (
	twoKeySchema            = "tkey-eth-two-key-v1"
	twoKeyDefaultBundlePath = "artifacts/two-key-bind.json"
	tillitisVendorPubKeyHex = "14274d3570097aea209af1c23b64aa439a4d0d32c62735c5f6d6a29600c9a275"
	defaultTKeyBinsDir      = "vendor/tkey-verification/bins"
)

var knownFirmwares = map[string]knownFirmware{
	"01337080": {Size: 4192},
	"01337081": {Size: 4192},
	"01337082": {Size: 4160},
}

type knownFirmware struct {
	Size int
}

type twoKeyBundle struct {
	Schema                   string                 `json:"schema"`
	Phase                    string                 `json:"phase"`
	CreatedAt                string                 `json:"created_at,omitempty"`
	Claim                    string                 `json:"claim"`
	Limitation               string                 `json:"limitation"`
	UDI                      string                 `json:"udi"`
	VendorID                 uint16                 `json:"vendor_id"`
	ProductID                uint8                  `json:"product_id"`
	ProductRev               uint8                  `json:"product_rev"`
	TillitisIdentity         twoKeyTillitisIdentity `json:"tillitis_identity"`
	WalletApp                *twoKeyWalletApp       `json:"wallet_app,omitempty"`
	WalletPubkeyUncompressed string                 `json:"wallet_pubkey_uncompressed,omitempty"`
	WalletAddress            string                 `json:"wallet_address,omitempty"`
	BindingHashSHA256        string                 `json:"binding_hash_sha256,omitempty"`
	WalletSignature          string                 `json:"wallet_signature,omitempty"`
	TillitisBindingSignature string                 `json:"tillitis_binding_signature,omitempty"`
}

type twoKeyTillitisIdentity struct {
	VerificationURL     string          `json:"verification_url"`
	VerificationJSON    json.RawMessage `json:"verification_json"`
	VerificationSHA256  string          `json:"verification_sha256"`
	VerificationAppTag  string          `json:"verification_app_tag"`
	VerificationAppHash string          `json:"verification_app_hash"`
	FirmwareSHA512      string          `json:"firmware_sha512"`
	IdentityPubkey      string          `json:"identity_pubkey"`
}

type twoKeyWalletApp struct {
	Name0         string `json:"name0"`
	Name1         string `json:"name1"`
	Version       uint32 `json:"version"`
	LoadedFrom    string `json:"loaded_from"`
	DigestSHA256  string `json:"digest_sha256"`
	DigestBLAKE2s string `json:"digest_blake2s"`
}

func runTwoKeyInit(args []string) error {
	fs := flag.NewFlagSet("bind-two-key-init", flag.ContinueOnError)
	var outPath, port, binsDir string
	fs.StringVar(&port, "port", "", "Serial device path")
	fs.StringVar(&outPath, "out", twoKeyDefaultBundlePath, "Path to write bundle JSON")
	fs.StringVar(&binsDir, "tkey-bins", defaultTKeyBinsDir, "Directory containing tkey-verification signer app binaries")
	if err := fs.Parse(args); err != nil {
		return err
	}

	tk, udi, err := openFirmwareTKey(port, false)
	if err != nil {
		return err
	}
	defer tk.Close()

	fw, err := lookupKnownFirmware(*udi)
	if err != nil {
		return err
	}
	evidence, err := fetchTillitisEvidence(udiHexBE(*udi))
	if err != nil {
		return err
	}
	if err := verifyTillitisEvidence(*evidence, udiHexBE(*udi)); err != nil {
		return err
	}
	appHash, appTag, err := parseTillitisVerificationMeta(evidence.VerificationJSON)
	if err != nil {
		return err
	}
	appPath, err := resolveTillitisSignerApp(appHash, binsDir)
	if err != nil {
		return err
	}
	identityPubkey, firmwareHash, err := loadTillitisSignerIdentity(tk, appPath, fw.Size)
	if err != nil {
		return err
	}

	bundle := twoKeyBundle{
		Schema:     twoKeySchema,
		Phase:      "identity-ready",
		Claim:      "Both a Tillitis identity key and the Ethereum wallet key signed the same wallet-binding statement.",
		Limitation: "This is a two-signature binding. It is stronger than a wallet-only statement, but it still depends on trusting the wallet app build to derive the wallet key only from Tillitis CDI-bound state.",
		UDI:        udiHexBE(*udi),
		VendorID:   udi.VendorID,
		ProductID:  udi.ProductID,
		ProductRev: udi.ProductRevision,
		TillitisIdentity: twoKeyTillitisIdentity{
			VerificationURL:     evidence.VerificationURL,
			VerificationJSON:    evidence.VerificationJSON,
			VerificationSHA256:  evidence.VerificationSHA256,
			VerificationAppTag:  appTag,
			VerificationAppHash: appHash,
			FirmwareSHA512:      hex.EncodeToString(firmwareHash),
			IdentityPubkey:      hex.EncodeToString(identityPubkey),
		},
	}
	return writeJSON(outPath, bundle)
}

func runTwoKeyWallet(args []string) error {
	fs := flag.NewFlagSet("bind-two-key-wallet", flag.ContinueOnError)
	var cfg commonFlags
	var bundlePath string
	addCommonFlags(fs, &cfg)
	fs.StringVar(&bundlePath, "bundle", twoKeyDefaultBundlePath, "Path to bundle JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := readTwoKeyBundle(bundlePath)
	if err != nil {
		return err
	}
	if bundle.Schema != twoKeySchema {
		return fmt.Errorf("unexpected bundle schema %q", bundle.Schema)
	}

	pw, err := prepareWallet(cfg, false)
	if err != nil {
		return err
	}
	defer pw.Close()

	hostSHA256, err := fileSHA256Hex(cfg.appPath)
	if err != nil {
		return err
	}
	hostBLAKE2s, err := fileBLAKE2sHex(cfg.appPath)
	if err != nil {
		return err
	}
	deviceDigest, err := pw.signer.GetAppDigest()
	if err != nil {
		return err
	}
	if hex.EncodeToString(deviceDigest) != hostBLAKE2s {
		return fmt.Errorf("wallet app digest mismatch: device %x host %s", deviceDigest, hostBLAKE2s)
	}
	addr, err := ethereumAddress(pw.pubkey)
	if err != nil {
		return err
	}

	bundle.WalletApp = &twoKeyWalletApp{
		Name0:         pw.appName.Name0,
		Name1:         pw.appName.Name1,
		Version:       pw.appName.Version,
		LoadedFrom:    filepath.Clean(cfg.appPath),
		DigestSHA256:  hostSHA256,
		DigestBLAKE2s: hostBLAKE2s,
	}
	bundle.WalletPubkeyUncompressed = "0x04" + hex.EncodeToString(pw.pubkey)
	bundle.WalletAddress = addr.Hex()

	hash, err := twoKeyBindingHash(bundle)
	if err != nil {
		return err
	}
	rawSig, err := pw.signer.SignDigest(hash[:])
	if err != nil {
		return err
	}
	ethSig, recoveredAddr, err := finalizeEthereumSignature(hash[:], pw.pubkey, rawSig)
	if err != nil {
		return err
	}
	if recoveredAddr != addr {
		return fmt.Errorf("recovered address %s does not match wallet address %s", recoveredAddr.Hex(), addr.Hex())
	}
	bundle.BindingHashSHA256 = hex.EncodeToString(hash[:])
	bundle.WalletSignature = hexutil.Encode(ethSig)
	bundle.Phase = "wallet-signed"
	return writeJSON(bundlePath, bundle)
}

func runTwoKeyFinalize(args []string) error {
	fs := flag.NewFlagSet("bind-two-key-finalize", flag.ContinueOnError)
	var port, bundlePath, binsDir string
	fs.StringVar(&port, "port", "", "Serial device path")
	fs.StringVar(&bundlePath, "bundle", twoKeyDefaultBundlePath, "Path to bundle JSON")
	fs.StringVar(&binsDir, "tkey-bins", defaultTKeyBinsDir, "Directory containing tkey-verification signer app binaries")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := readTwoKeyBundle(bundlePath)
	if err != nil {
		return err
	}
	if bundle.BindingHashSHA256 == "" || bundle.WalletSignature == "" || bundle.WalletApp == nil {
		return errors.New("bundle is missing wallet signature state")
	}

	tk, udi, err := openFirmwareTKey(port, false)
	if err != nil {
		return err
	}
	defer tk.Close()
	if udiHexBE(*udi) != bundle.UDI {
		return fmt.Errorf("UDI mismatch: live %s bundle %s", udiHexBE(*udi), bundle.UDI)
	}
	appPath, err := resolveTillitisSignerApp(bundle.TillitisIdentity.VerificationAppHash, binsDir)
	if err != nil {
		return err
	}
	fw, err := lookupKnownFirmware(*udi)
	if err != nil {
		return err
	}
	identityPubkey, firmwareHash, err := loadTillitisSignerIdentity(tk, appPath, fw.Size)
	if err != nil {
		return err
	}
	if hex.EncodeToString(identityPubkey) != bundle.TillitisIdentity.IdentityPubkey {
		return errors.New("Tillitis identity pubkey mismatch")
	}
	if hex.EncodeToString(firmwareHash) != bundle.TillitisIdentity.FirmwareSHA512 {
		return errors.New("firmware hash mismatch")
	}

	hash, err := decodeHex32(bundle.BindingHashSHA256)
	if err != nil {
		return err
	}
	signer := tkeysign.New(tk)
	tSig, err := signer.Sign(hash[:])
	if err != nil {
		return err
	}
	bundle.TillitisBindingSignature = hex.EncodeToString(tSig)
	bundle.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	bundle.Phase = "complete"
	return writeJSON(bundlePath, bundle)
}

func runTwoKeyVerify(args []string) error {
	fs := flag.NewFlagSet("verify-two-key", flag.ContinueOnError)
	var bundlePath string
	fs.StringVar(&bundlePath, "bundle", twoKeyDefaultBundlePath, "Path to bundle JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := readTwoKeyBundle(bundlePath)
	if err != nil {
		return err
	}
	if bundle.Schema != twoKeySchema {
		return fmt.Errorf("unexpected bundle schema %q", bundle.Schema)
	}
	if bundle.Phase != "complete" {
		return fmt.Errorf("bundle phase %q is not complete", bundle.Phase)
	}
	if err := verifyTillitisIdentityBundle(bundle); err != nil {
		return err
	}
	hash, err := twoKeyBindingHash(bundle)
	if err != nil {
		return err
	}
	if bundle.BindingHashSHA256 != hex.EncodeToString(hash[:]) {
		return errors.New("binding hash mismatch")
	}
	tSig, err := decodeHexString(bundle.TillitisBindingSignature)
	if err != nil {
		return err
	}
	pubkey, err := decodeHexString(bundle.TillitisIdentity.IdentityPubkey)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubkey), hash[:], tSig) {
		return errors.New("Tillitis binding signature invalid")
	}
	wSig, err := decodeHexString(bundle.WalletSignature)
	if err != nil {
		return err
	}
	if err := verifyWalletBindingSignature(bundle, hash[:], wSig); err != nil {
		return err
	}
	fmt.Println("two-key bundle: ok")
	return nil
}

func readTwoKeyBundle(path string) (twoKeyBundle, error) {
	var bundle twoKeyBundle
	b, err := os.ReadFile(path)
	if err != nil {
		return bundle, err
	}
	err = json.Unmarshal(b, &bundle)
	return bundle, err
}

func verifyTillitisIdentityBundle(bundle twoKeyBundle) error {
	e := tillitisEvidence{
		VerificationURL:    bundle.TillitisIdentity.VerificationURL,
		VerificationJSON:   bundle.TillitisIdentity.VerificationJSON,
		VerificationSHA256: bundle.TillitisIdentity.VerificationSHA256,
	}
	if err := verifyTillitisEvidence(e, bundle.UDI); err != nil {
		return err
	}
	var parsed struct {
		AppTag    string `json:"apptag"`
		AppHash   string `json:"apphash"`
		Signature string `json:"signature"`
		Proof     string `json:"proof"`
	}
	if err := json.Unmarshal(bundle.TillitisIdentity.VerificationJSON, &parsed); err != nil {
		return err
	}
	if parsed.AppTag != bundle.TillitisIdentity.VerificationAppTag {
		return errors.New("verification app tag mismatch")
	}
	if parsed.AppHash != bundle.TillitisIdentity.VerificationAppHash {
		return errors.New("verification app hash mismatch")
	}
	if parsed.Signature == "" {
		return errors.New("only direct vendor signatures are supported for two-key offline verification")
	}
	sig, err := decodeHexString(parsed.Signature)
	if err != nil {
		return err
	}
	vendorPub, err := decodeHexString(tillitisVendorPubKeyHex)
	if err != nil {
		return err
	}
	fwHash, err := decodeHexString(bundle.TillitisIdentity.FirmwareSHA512)
	if err != nil {
		return err
	}
	identityPub, err := decodeHexString(bundle.TillitisIdentity.IdentityPubkey)
	if err != nil {
		return err
	}
	msg, err := buildTillitisVendorMessage(bundle.UDI, fwHash, identityPub)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(vendorPub), msg, sig) {
		return errors.New("Tillitis vendor signature invalid")
	}
	return nil
}

func verifyWalletBindingSignature(bundle twoKeyBundle, hash []byte, sig []byte) error {
	recovered, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return err
	}
	recoveredRaw := crypto.FromECDSAPub(recovered)
	wantPub, err := decodeHexString(bundle.WalletPubkeyUncompressed)
	if err != nil {
		return err
	}
	if !bytes.Equal(recoveredRaw, wantPub) {
		return errors.New("wallet signature does not recover wallet pubkey")
	}
	addr, err := ethereumAddress(wantPub[1:])
	if err != nil {
		return err
	}
	if addr.Hex() != bundle.WalletAddress {
		return errors.New("wallet address does not match wallet pubkey")
	}
	return nil
}

func twoKeyBindingHash(bundle twoKeyBundle) ([32]byte, error) {
	var out [32]byte
	payload, err := encodeTwoKeyBindingPayload(bundle)
	if err != nil {
		return out, err
	}
	return sha256.Sum256(payload), nil
}

func encodeTwoKeyBindingPayload(bundle twoKeyBundle) ([]byte, error) {
	if bundle.WalletApp == nil {
		return nil, errors.New("wallet app missing")
	}
	udi, err := decodeHexString(bundle.UDI)
	if err != nil {
		return nil, err
	}
	fwHash, err := decodeHexString(bundle.TillitisIdentity.FirmwareSHA512)
	if err != nil {
		return nil, err
	}
	if len(fwHash) != sha512.Size {
		return nil, errors.New("firmware hash must be sha512")
	}
	veriPub, err := decodeHexString(bundle.TillitisIdentity.IdentityPubkey)
	if err != nil {
		return nil, err
	}
	if len(veriPub) != ed25519.PublicKeySize {
		return nil, errors.New("Tillitis identity pubkey must be 32 bytes")
	}
	veriAppHash, err := decodeHexString(bundle.TillitisIdentity.VerificationAppHash)
	if err != nil {
		return nil, err
	}
	if len(veriAppHash) != sha512.Size {
		return nil, errors.New("verification app hash must be sha512")
	}
	wSHA256, err := decodeHexString(bundle.WalletApp.DigestSHA256)
	if err != nil {
		return nil, err
	}
	if len(wSHA256) != sha256.Size {
		return nil, errors.New("wallet app sha256 must be 32 bytes")
	}
	wB2s, err := decodeHexString(bundle.WalletApp.DigestBLAKE2s)
	if err != nil {
		return nil, err
	}
	if len(wB2s) != 32 {
		return nil, errors.New("wallet app blake2s must be 32 bytes")
	}
	wPub, err := decodeHexString(bundle.WalletPubkeyUncompressed)
	if err != nil {
		return nil, err
	}
	if len(wPub) != 65 || wPub[0] != 0x04 {
		return nil, errors.New("wallet pubkey must be uncompressed 65 bytes")
	}
	addr := common.HexToAddress(bundle.WalletAddress).Bytes()

	buf := make([]byte, 0, 8+8+2+1+1+64+32+64+4+4+4+32+32+65+20)
	buf = append(buf, []byte("TKEY2K1")...)
	buf = append(buf, udi...)
	tmp2 := make([]byte, 2)
	tmp4 := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp2, bundle.VendorID)
	buf = append(buf, tmp2...)
	buf = append(buf, bundle.ProductID, bundle.ProductRev)
	buf = append(buf, fwHash...)
	buf = append(buf, veriPub...)
	buf = append(buf, veriAppHash...)
	buf = appendFixed4(buf, bundle.WalletApp.Name0)
	buf = appendFixed4(buf, bundle.WalletApp.Name1)
	binary.BigEndian.PutUint32(tmp4, bundle.WalletApp.Version)
	buf = append(buf, tmp4...)
	buf = append(buf, wSHA256...)
	buf = append(buf, wB2s...)
	buf = append(buf, wPub...)
	buf = append(buf, addr...)
	return buf, nil
}

func parseTillitisVerificationMeta(raw json.RawMessage) (appHash string, appTag string, err error) {
	var parsed struct {
		AppTag  string `json:"apptag"`
		AppHash string `json:"apphash"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", err
	}
	if parsed.AppHash == "" || parsed.AppTag == "" {
		return "", "", errors.New("Tillitis verification JSON missing app metadata")
	}
	return parsed.AppHash, parsed.AppTag, nil
}

func resolveTillitisSignerApp(appHash, dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bin") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		sum, err := fileSHA512Hex(path)
		if err != nil {
			return "", err
		}
		if sum == appHash {
			return path, nil
		}
	}
	return "", fmt.Errorf("no local Tillitis signer app matches hash %s", appHash)
}

func loadTillitisSignerIdentity(tk *tkeyclient.TillitisKey, appPath string, firmwareSize int) ([]byte, []byte, error) {
	bin, err := os.ReadFile(appPath)
	if err != nil {
		return nil, nil, err
	}
	if err := tk.LoadApp(bin, nil); err != nil {
		return nil, nil, err
	}
	signer := tkeysign.New(tk)
	pubkey, err := signer.GetPubkey()
	if err != nil {
		return nil, nil, err
	}
	fwHash, err := signer.GetFWDigest(firmwareSize)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte{}, pubkey...), append([]byte{}, fwHash...), nil
}

func openFirmwareTKey(port string, verbose bool) (*tkeyclient.TillitisKey, *tkeyclient.UDI, error) {
	if !verbose {
		tkeyclient.SilenceLogging()
	}
	if port == "" {
		var err error
		port, err = tkeyclient.DetectSerialPort(false)
		if err != nil {
			return nil, nil, err
		}
	}
	tk := tkeyclient.New()
	if err := tk.Connect(port); err != nil {
		return nil, nil, err
	}
	nameVer, err := tk.GetNameVersion()
	if err != nil {
		tk.Close()
		return nil, nil, errors.New("device not in firmware mode; replug and retry")
	}
	if nameVer.Name0 != "tk1 " || nameVer.Name1 != "mkdf" {
		tk.Close()
		return nil, nil, errors.New("unexpected firmware identity")
	}
	udi, err := tk.GetUDI()
	if err != nil {
		tk.Close()
		return nil, nil, err
	}
	return tk, udi, nil
}

func lookupKnownFirmware(udi tkeyclient.UDI) (knownFirmware, error) {
	key := hex.EncodeToString(udiBytesBE(udi)[:4])
	fw, ok := knownFirmwares[key]
	if !ok {
		return knownFirmware{}, fmt.Errorf("unknown firmware mapping for UDI0 %s", key)
	}
	return fw, nil
}

func buildTillitisVendorMessage(udiHex string, fwHash []byte, pubKey []byte) ([]byte, error) {
	udi, err := decodeHexString(udiHex)
	if err != nil {
		return nil, err
	}
	if len(udi) != 8 {
		return nil, errors.New("UDI must be 8 bytes")
	}
	if len(fwHash) != sha512.Size {
		return nil, errors.New("firmware hash must be 64 bytes")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, errors.New("Tillitis identity pubkey must be 32 bytes")
	}
	msg := make([]byte, 0, len(udi)+len(fwHash)+len(pubKey))
	msg = append(msg, udi...)
	msg = append(msg, fwHash...)
	msg = append(msg, pubKey...)
	return msg, nil
}

func fileSHA512Hex(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:]), nil
}
