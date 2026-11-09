package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type signOutput struct {
	Address   string `json:"address"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
}

type signTxOutput struct {
	Address        string `json:"address"`
	Digest         string `json:"digest"`
	Signature      string `json:"signature"`
	RawTransaction string `json:"raw_transaction"`
	TxHash         string `json:"tx_hash"`
}

type signTypedOutput struct {
	Address   string `json:"address"`
	Digest    string `json:"digest"`
	Signature string `json:"signature"`
	Encoded   string `json:"encoded"`
}

func runSignTx(args []string) error {
	fs := flag.NewFlagSet("sign-tx", flag.ContinueOnError)
	var cfg commonFlags
	var txPath string
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.StringVar(&txPath, "tx", "-", "Path to unsigned transaction JSON, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	txJSON, err := readInput(txPath)
	if err != nil {
		return err
	}
	tx, signer, err := parseUnsignedTransaction(txJSON)
	if err != nil {
		return err
	}
	digest := signer.Hash(tx)

	pubkey, sig, err := signDigestWithSigner(cfg, digest.Bytes())
	if err != nil {
		return err
	}
	ethSig, addr, err := finalizeEthereumSignature(digest.Bytes(), pubkey, sig)
	if err != nil {
		return err
	}
	signedTx, err := tx.WithSignature(signer, ethSig)
	if err != nil {
		return err
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		return err
	}
	recovered, err := types.Sender(signer, signedTx)
	if err != nil {
		return err
	}
	if recovered != addr {
		return fmt.Errorf("recovered sender %s does not match signer %s", recovered.Hex(), addr.Hex())
	}

	return writeJSONStdout(signTxOutput{
		Address:        addr.Hex(),
		Digest:         hexutil.Encode(digest.Bytes()),
		Signature:      hexutil.Encode(ethSig),
		RawTransaction: hexutil.Encode(rawTx),
		TxHash:         signedTx.Hash().Hex(),
	})
}

func runSignPersonal(args []string) error {
	fs := flag.NewFlagSet("sign-personal", flag.ContinueOnError)
	var cfg commonFlags
	var msg string
	var msgHex string
	var msgPath string
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.StringVar(&msg, "message", "", "UTF-8 message string")
	fs.StringVar(&msgHex, "message-hex", "", "Message bytes as hex")
	fs.StringVar(&msgPath, "message-file", "", "Path to message bytes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	data, err := readMessageInput(msg, msgHex, msgPath)
	if err != nil {
		return err
	}
	hash, _ := accounts.TextAndHash(data)
	pubkey, sig, err := signDigestWithSigner(cfg, hash)
	if err != nil {
		return err
	}
	ethSig, addr, err := finalizeEthereumSignature(hash, pubkey, sig)
	if err != nil {
		return err
	}
	if err := verifyRecoveredSignature(hash, ethSig, addr); err != nil {
		return err
	}
	return writeJSONStdout(signOutput{
		Address:   addr.Hex(),
		Digest:    hexutil.Encode(hash),
		Signature: hexutil.Encode(ethSig),
	})
}

func runSignTypedData(args []string) error {
	fs := flag.NewFlagSet("sign-typed-data", flag.ContinueOnError)
	var cfg commonFlags
	var typedPath string
	addCommonFlags(fs, &cfg)
	addPathFlag(fs, &cfg)
	fs.StringVar(&typedPath, "typed-data", "-", "Path to EIP-712 typed data JSON, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	body, err := readInput(typedPath)
	if err != nil {
		return err
	}
	var typedData apitypes.TypedData
	if err := json.Unmarshal(body, &typedData); err != nil {
		return fmt.Errorf("typed data JSON: %w", err)
	}
	hash, encoded, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return err
	}
	pubkey, sig, err := signDigestWithSigner(cfg, hash)
	if err != nil {
		return err
	}
	ethSig, addr, err := finalizeEthereumSignature(hash, pubkey, sig)
	if err != nil {
		return err
	}
	if err := verifyRecoveredSignature(hash, ethSig, addr); err != nil {
		return err
	}
	return writeJSONStdout(signTypedOutput{
		Address:   addr.Hex(),
		Digest:    hexutil.Encode(hash),
		Signature: hexutil.Encode(ethSig),
		Encoded:   encoded,
	})
}

func signDigestWithSigner(cfg commonFlags, digest []byte) ([]byte, []byte, error) {
	type result struct {
		pubkey []byte
		sig    []byte
	}
	out, err := withSigner(cfg, func(s *ethSigner) (*result, error) {
		pubkey, err := s.GetPubkey()
		if err != nil {
			return nil, err
		}
		sig, err := s.SignDigest(digest)
		if err != nil {
			return nil, err
		}
		return &result{pubkey: pubkey, sig: sig}, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return out.pubkey, out.sig, nil
}

func readMessageInput(msg string, msgHex string, msgPath string) ([]byte, error) {
	n := 0
	if msg != "" {
		n++
	}
	if msgHex != "" {
		n++
	}
	if msgPath != "" {
		n++
	}
	if n != 1 {
		return nil, errors.New("exactly one of --message, --message-hex, or --message-file is required")
	}
	if msg != "" {
		return []byte(msg), nil
	}
	if msgHex != "" {
		return decodeHexString(msgHex)
	}
	return os.ReadFile(msgPath)
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return os.ReadFile("/dev/stdin")
	}
	return os.ReadFile(path)
}

func writeJSONStdout(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = os.Stdout.Write(b)
	return err
}

func parseUnsignedTransaction(body []byte) (*types.Transaction, types.Signer, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return nil, nil, fmt.Errorf("transaction JSON: %w", err)
	}

	txType, err := parseTxType(raw["type"])
	if err != nil {
		return nil, nil, err
	}
	chainID, err := parseBigIntField(raw, "chainId", txType != types.LegacyTxType)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := parseUint64Field(raw, "nonce", true)
	if err != nil {
		return nil, nil, err
	}
	gas, err := parseUint64Field(raw, "gas", true)
	if err != nil {
		return nil, nil, err
	}
	to, err := parseAddressPtrField(raw, "to")
	if err != nil {
		return nil, nil, err
	}
	value, err := parseBigIntField(raw, "value", false)
	if err != nil {
		return nil, nil, err
	}
	if value == nil {
		value = new(big.Int)
	}
	data, err := parseBytesField(raw, "data")
	if err != nil {
		return nil, nil, err
	}
	accessList, err := parseAccessListField(raw, "accessList")
	if err != nil {
		return nil, nil, err
	}

	var txData types.TxData
	switch txType {
	case types.LegacyTxType:
		gasPrice, err := parseBigIntField(raw, "gasPrice", true)
		if err != nil {
			return nil, nil, err
		}
		txData = &types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gas,
			To:       to,
			Value:    value,
			Data:     data,
		}
	case types.AccessListTxType:
		gasPrice, err := parseBigIntField(raw, "gasPrice", true)
		if err != nil {
			return nil, nil, err
		}
		txData = &types.AccessListTx{
			ChainID:    chainID,
			Nonce:      nonce,
			GasPrice:   gasPrice,
			Gas:        gas,
			To:         to,
			Value:      value,
			Data:       data,
			AccessList: accessList,
		}
	case types.DynamicFeeTxType:
		tip, err := parseBigIntField(raw, "maxPriorityFeePerGas", true)
		if err != nil {
			return nil, nil, err
		}
		feeCap, err := parseBigIntField(raw, "maxFeePerGas", true)
		if err != nil {
			return nil, nil, err
		}
		txData = &types.DynamicFeeTx{
			ChainID:    chainID,
			Nonce:      nonce,
			GasTipCap:  tip,
			GasFeeCap:  feeCap,
			Gas:        gas,
			To:         to,
			Value:      value,
			Data:       data,
			AccessList: accessList,
		}
	default:
		return nil, nil, fmt.Errorf("unsupported tx type %d", txType)
	}

	tx := types.NewTx(txData)
	signer := signerForTxType(chainID, txType)
	return tx, signer, nil
}

func signerForTxType(chainID *big.Int, txType uint8) types.Signer {
	if txType == types.LegacyTxType && chainID == nil {
		return types.HomesteadSigner{}
	}
	if chainID == nil {
		chainID = big.NewInt(0)
	}
	return types.LatestSignerForChainID(chainID)
}

func parseTxType(v any) (uint8, error) {
	if v == nil {
		return types.LegacyTxType, nil
	}
	n, err := parseUint64(v)
	if err != nil {
		return 0, fmt.Errorf("type: %w", err)
	}
	if n > 0xff {
		return 0, fmt.Errorf("type %d out of range", n)
	}
	return uint8(n), nil
}

func parseUint64Field(raw map[string]any, name string, required bool) (uint64, error) {
	v, ok := raw[name]
	if !ok || v == nil {
		if required {
			return 0, fmt.Errorf("missing %q", name)
		}
		return 0, nil
	}
	n, err := parseUint64(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

func parseBigIntField(raw map[string]any, name string, required bool) (*big.Int, error) {
	v, ok := raw[name]
	if !ok || v == nil {
		if required {
			return nil, fmt.Errorf("missing %q", name)
		}
		return nil, nil
	}
	n, err := parseBigInt(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

func parseAddressPtrField(raw map[string]any, name string) (*common.Address, error) {
	v, ok := raw[name]
	if !ok || v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s: expected string", name)
	}
	if s == "" {
		return nil, nil
	}
	if !common.IsHexAddress(s) {
		return nil, fmt.Errorf("%s: invalid address %q", name, s)
	}
	addr := common.HexToAddress(s)
	return &addr, nil
}

func parseBytesField(raw map[string]any, name string) ([]byte, error) {
	v, ok := raw[name]
	if !ok || v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s: expected string", name)
	}
	return decodeHexString(s)
}

func parseAccessListField(raw map[string]any, name string) (types.AccessList, error) {
	v, ok := raw[name]
	if !ok || v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected array", name)
	}
	accessList := make(types.AccessList, 0, len(items))
	for i, item := range items {
		entryMap, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: expected object", name, i)
		}
		addrVal, ok := entryMap["address"]
		if !ok {
			return nil, fmt.Errorf("%s[%d]: missing address", name, i)
		}
		addrStr, ok := addrVal.(string)
		if !ok || !common.IsHexAddress(addrStr) {
			return nil, fmt.Errorf("%s[%d]: invalid address", name, i)
		}
		keyVals, ok := entryMap["storageKeys"]
		if !ok {
			return nil, fmt.Errorf("%s[%d]: missing storageKeys", name, i)
		}
		keyItems, ok := keyVals.([]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: storageKeys must be array", name, i)
		}
		keys := make([]common.Hash, 0, len(keyItems))
		for j, keyVal := range keyItems {
			keyStr, ok := keyVal.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d].storageKeys[%d]: expected string", name, i, j)
			}
			b, err := decodeHexString(keyStr)
			if err != nil || len(b) != 32 {
				return nil, fmt.Errorf("%s[%d].storageKeys[%d]: expected 32-byte hex value", name, i, j)
			}
			keys = append(keys, common.BytesToHash(b))
		}
		accessList = append(accessList, types.AccessTuple{
			Address:     common.HexToAddress(addrStr),
			StorageKeys: keys,
		})
	}
	return accessList, nil
}

func parseUint64(v any) (uint64, error) {
	switch x := v.(type) {
	case json.Number:
		return strconv.ParseUint(x.String(), 10, 64)
	case float64:
		if x < 0 || x != float64(uint64(x)) {
			return 0, fmt.Errorf("invalid integer %v", x)
		}
		return uint64(x), nil
	case string:
		if strings.HasPrefix(x, "0x") || strings.HasPrefix(x, "0X") {
			return strconv.ParseUint(x[2:], 16, 64)
		}
		return strconv.ParseUint(x, 10, 64)
	default:
		return 0, fmt.Errorf("expected integer or string, got %T", v)
	}
}

func parseBigInt(v any) (*big.Int, error) {
	switch x := v.(type) {
	case json.Number:
		n, ok := new(big.Int).SetString(x.String(), 10)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", x.String())
		}
		return n, nil
	case float64:
		if x < 0 || x != float64(uint64(x)) {
			return nil, fmt.Errorf("invalid integer %v", x)
		}
		return new(big.Int).SetUint64(uint64(x)), nil
	case string:
		base := 10
		s := x
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			base = 16
			s = s[2:]
		}
		n, ok := new(big.Int).SetString(s, base)
		if !ok {
			return nil, fmt.Errorf("invalid integer %q", x)
		}
		return n, nil
	default:
		return nil, fmt.Errorf("expected integer or string, got %T", v)
	}
}

func verifyRecoveredSignature(digest []byte, sig []byte, expected common.Address) error {
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		return err
	}
	recovered := crypto.PubkeyToAddress(*pub)
	if recovered != expected {
		return fmt.Errorf("recovered address %s does not match %s", recovered.Hex(), expected.Hex())
	}
	return nil
}
