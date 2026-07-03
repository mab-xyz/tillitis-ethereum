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

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "address":
		if err := runAddress(os.Args[2:]); err != nil {
			logger.Printf("address: %v", err)
			os.Exit(1)
		}
	case "sign-digest":
		if err := runSignDigest(os.Args[2:]); err != nil {
			logger.Printf("sign-digest: %v", err)
			os.Exit(1)
		}
	case "sign-tx":
		if err := runSignTx(os.Args[2:]); err != nil {
			logger.Printf("sign-tx: %v", err)
			os.Exit(1)
		}
	case "sign-personal":
		if err := runSignPersonal(os.Args[2:]); err != nil {
			logger.Printf("sign-personal: %v", err)
			os.Exit(1)
		}
	case "sign-typed-data":
		if err := runSignTypedData(os.Args[2:]); err != nil {
			logger.Printf("sign-typed-data: %v", err)
			os.Exit(1)
		}
	case "verify-live":
		if err := runVerifyLive(os.Args[2:]); err != nil {
			logger.Printf("verify-live: %v", err)
			os.Exit(1)
		}
	case "bind-two-key-init":
		if err := runTwoKeyInit(os.Args[2:]); err != nil {
			logger.Printf("bind-two-key-init: %v", err)
			os.Exit(1)
		}
	case "bind-two-key-wallet":
		if err := runTwoKeyWallet(os.Args[2:]); err != nil {
			logger.Printf("bind-two-key-wallet: %v", err)
			os.Exit(1)
		}
	case "bind-two-key-finalize":
		if err := runTwoKeyFinalize(os.Args[2:]); err != nil {
			logger.Printf("bind-two-key-finalize: %v", err)
			os.Exit(1)
		}
	case "verify-two-key":
		if err := runTwoKeyVerify(os.Args[2:]); err != nil {
			logger.Printf("verify-two-key: %v", err)
			os.Exit(1)
		}
	case "attest":
		if err := runAttest(os.Args[2:]); err != nil {
			logger.Printf("attest: %v", err)
			os.Exit(1)
		}
	case "prove":
		if err := runProve(os.Args[2:]); err != nil {
			logger.Printf("prove: %v", err)
			os.Exit(1)
		}
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			logger.Printf("verify: %v", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <address|sign-digest|sign-tx|sign-personal|sign-typed-data|verify-live|bind-two-key-init|bind-two-key-wallet|bind-two-key-finalize|verify-two-key|attest|prove|verify> [flags]\n", filepath.Base(os.Args[0]))
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
}

func addCommonFlags(fs *flag.FlagSet, cfg *commonFlags) {
	fs.StringVar(&cfg.port, "port", "", "Serial device path")
	fs.StringVar(&cfg.appPath, "app", defaultAppPath(), "Path to device app binary")
	fs.StringVar(&cfg.ussFile, "uss-file", "", "Load app with USS file")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Verbose logging")
}

func runAddress(args []string) error {
	fs := flag.NewFlagSet("address", flag.ContinueOnError)
	var cfg commonFlags
	addCommonFlags(fs, &cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}

	pubkey, err := withSigner(cfg, func(s *ethSigner) ([]byte, error) {
		return s.GetPubkey()
	})
	if err != nil {
		return err
	}

	addr, err := ethereumAddress(pubkey)
	if err != nil {
		return err
	}

	fmt.Printf("pubkey=0x%s\n", hex.EncodeToString(pubkey))
	fmt.Printf("address=%s\n", addr.Hex())
	return nil
}

func runSignDigest(args []string) error {
	fs := flag.NewFlagSet("sign-digest", flag.ContinueOnError)
	var cfg commonFlags
	var digestHex string
	addCommonFlags(fs, &cfg)
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

	type result struct {
		pubkey []byte
		sig    []byte
	}
	out, err := withSigner(cfg, func(s *ethSigner) (*result, error) {
		pubkey, err := s.GetPubkey()
		if err != nil {
			return nil, err
		}
		sig, err := s.SignDigest(digest[:])
		if err != nil {
			return nil, err
		}
		return &result{pubkey: pubkey, sig: sig}, nil
	})
	if err != nil {
		return err
	}

	ethSig, addr, err := finalizeEthereumSignature(digest[:], out.pubkey, out.sig)
	if err != nil {
		return err
	}

	fmt.Printf("address=%s\n", addr.Hex())
	fmt.Printf("signature=0x%s\n", hex.EncodeToString(ethSig))
	return nil
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

	app, err := os.ReadFile(cfg.appPath)
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
	if err := ensureAppLoaded(tk, s, app, uss); err != nil {
		return zero, err
	}

	return fn(&s)
}

func ensureAppLoaded(tk *tkeyclient.TillitisKey, s ethSigner, app []byte, uss []byte) error {
	nameVer, err := tk.GetNameVersion()
	if err == nil && nameVer.Name0 == "tk1 " && nameVer.Name1 == "mkdf" {
		return tk.LoadApp(app, uss)
	}

	appName, err := s.GetAppNameVersion()
	if err != nil {
		return fmt.Errorf("device not in firmware mode and eth app not running: %w", err)
	}
	if appName.Name0 != "eth " || appName.Name1 != "sign" {
		return fmt.Errorf("unexpected app running: %q/%q", appName.Name0, appName.Name1)
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
