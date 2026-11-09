package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tillitis/tkeyclient"
)

var logger = log.New(os.Stderr, "", 0)

// commands maps each subcommand to its implementation.
var commands = map[string]func(args []string) error{
	"address":               runAddress,
	"sign-digest":           runSignDigest,
	"sign-tx":               runSignTx,
	"sign-personal":         runSignPersonal,
	"sign-typed-data":       runSignTypedData,
	"verify-hd":             runVerifyHD,
	"verify-live":           runVerifyLive,
	"bind-two-key-init":     runTwoKeyInit,
	"bind-two-key-wallet":   runTwoKeyWallet,
	"bind-two-key-finalize": runTwoKeyFinalize,
	"verify-two-key":        runTwoKeyVerify,
	"attest":                runAttest,
	"prove":                 runProve,
	"verify":                runVerify,
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	run, ok := commands[os.Args[1]]
	if !ok {
		usage()
		os.Exit(2)
	}
	// `<command> --help` is a success: the flag package reports it as flag.ErrHelp after printing the usage.
	if err := run(os.Args[2:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		logger.Printf("%s: %v", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <address|sign-digest|sign-tx|sign-personal|sign-typed-data|verify-hd|verify-live|bind-two-key-init|bind-two-key-wallet|bind-two-key-finalize|verify-two-key|attest|prove|verify> [flags]\n", filepath.Base(os.Args[0]))
}

func defaultAppPath() string {
	return filepath.Join("device", "ethsign", "app.bin")
}

func defaultSelfAssertSeedPath() string {
	return filepath.Join("artifacts", "self-assert-seed.hex")
}

type commonFlags struct {
	port    string
	appPath string
	ussFile string
	verbose bool
	hdPath  string
}

func addCommonFlags(fs *flag.FlagSet, cfg *commonFlags) {
	fs.StringVar(&cfg.port, "device", "", "Serial device path of the TKey (default: detected)")
	fs.StringVar(&cfg.appPath, "app", defaultAppPath(), "Path to device app binary")
	fs.StringVar(&cfg.ussFile, "uss-file", "", "Load app with USS file")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Verbose logging")
}

// addPathFlag adds --path; only commands that open the device through withSigner support it.
func addPathFlag(fs *flag.FlagSet, cfg *commonFlags) {
	fs.StringVar(&cfg.hdPath, "path", "", "BIP-32 path, e.g. m/44'/60'/0'/0/0; uses the HD app (device/ethsign-hd) instead of the single-key app")
}

func runAddress(args []string) error {
	fs := flag.NewFlagSet("address", flag.ContinueOnError)
	var cfg commonFlags
	var asJSON bool
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.BoolVar(&asJSON, "json", false, "Print JSON instead of key=value lines")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pubkey, err := withSigner(cfg, func(s *ethSigner) ([]byte, error) {
		return s.GetPubkey()
	})
	if err != nil {
		return err
	}

	out, err := makeAddressOutput(pubkey)
	if err != nil {
		return err
	}
	if asJSON {
		return writeJSONStdout(out)
	}
	fmt.Printf("pubkey=%s\n", out.Pubkey)
	fmt.Printf("address=%s\n", out.Address)
	return nil
}

func runSignDigest(args []string) error {
	fs := flag.NewFlagSet("sign-digest", flag.ContinueOnError)
	var cfg commonFlags
	var digestHex string
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.StringVar(&digestHex, "digest", "", "32-byte digest as hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if digestHex == "" {
		return errors.New("missing --digest")
	}

	digest, err := decodeHex32(digestHex)
	if err != nil {
		return err
	}

	out, err := makeDigestOutput(deviceSigner(cfg), digest[:])
	if err != nil {
		return err
	}
	return writeJSONStdout(out)
}

func withSigner[T any](cfg commonFlags, fn func(*ethSigner) (T, error)) (T, error) {
	var zero T
	if !cfg.verbose {
		tkeyclient.SilenceLogging()
	}

	port := cfg.port
	if port == "" {
		var err error
		port, err = tkeyclient.DetectSerialPort(false)
		if err != nil {
			return zero, err
		}
	}

	var path []uint32
	appPath, wantName1 := cfg.appPath, legacyName1
	if cfg.hdPath != "" {
		var err error
		if path, err = parseHDPath(cfg.hdPath); err != nil {
			return zero, err
		}
		wantName1 = hdAppName1
		if appPath == defaultAppPath() {
			appPath = defaultHDAppPath()
		}
	}

	app, err := os.ReadFile(appPath)
	if err != nil {
		return zero, err
	}

	var uss []byte
	if cfg.ussFile != "" {
		uss, err = os.ReadFile(cfg.ussFile)
		if err != nil {
			return zero, err
		}
	}

	tk := tkeyclient.New()
	if err := tk.Connect(port); err != nil {
		return zero, err
	}
	defer tk.Close()

	s := newEthSigner(tk)
	s.path = path
	if err := ensureAppLoaded(tk, s, app, uss, wantName1); err != nil {
		return zero, err
	}

	return fn(&s)
}

func ensureAppLoaded(tk *tkeyclient.TillitisKey, s ethSigner, app []byte, uss []byte, wantName1 string) error {
	nameVer, err := tk.GetNameVersion()
	if err == nil && nameVer.Name0 == "tk1 " && nameVer.Name1 == "mkdf" {
		return tk.LoadApp(app, uss)
	}

	appName, err := s.GetAppNameVersion()
	if err != nil {
		return fmt.Errorf("device not in firmware mode and eth app not running: %w", err)
	}
	if appName.Name0 != "eth " || appName.Name1 != wantName1 {
		return fmt.Errorf("app %q/%q is running, need %q/%q; replug the TKey", appName.Name0, appName.Name1, "eth ", wantName1)
	}
	if len(uss) != 0 {
		return errors.New("app already running; replug to apply --uss-file")
	}
	return nil
}

func decodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := decodeHexString(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

func decodeHexString(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func ethereumAddress(pubkey []byte) (common.Address, error) {
	if len(pubkey) != 64 {
		return common.Address{}, fmt.Errorf("expected 64-byte pubkey, got %d", len(pubkey))
	}
	uncompressed := append([]byte{0x04}, pubkey...)
	parsed, err := crypto.UnmarshalPubkey(uncompressed)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*parsed), nil
}

func finalizeEthereumSignature(digest []byte, pubkey []byte, rawSig []byte) ([]byte, common.Address, error) {
	const secp256k1NHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	curveN, _ := new(big.Int).SetString(secp256k1NHex, 16)
	halfN := new(big.Int).Rsh(new(big.Int).Set(curveN), 1)

	if len(rawSig) != 64 {
		return nil, common.Address{}, fmt.Errorf("expected 64-byte signature, got %d", len(rawSig))
	}

	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])
	if s.Cmp(halfN) > 0 {
		s.Sub(curveN, s)
	}

	sig64 := make([]byte, 64)
	rb := r.Bytes()
	sb := s.Bytes()
	copy(sig64[32-len(rb):32], rb)
	copy(sig64[64-len(sb):], sb)

	addr, err := ethereumAddress(pubkey)
	if err != nil {
		return nil, common.Address{}, err
	}

	for v := byte(0); v < 2; v++ {
		sig65 := append(append([]byte{}, sig64...), v)
		recovered, err := crypto.SigToPub(digest, sig65)
		if err != nil {
			continue
		}
		recoveredRaw := crypto.FromECDSAPub(recovered)
		if len(recoveredRaw) == 65 && string(recoveredRaw[1:]) == string(pubkey) {
			return sig65, addr, nil
		}
	}

	return nil, common.Address{}, errors.New("could not recover matching public key")
}
