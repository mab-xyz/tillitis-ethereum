package main

// The JSON printed by the commands of the common CLI of hardware-backed Ethereum signers,
// https://github.com/mab-xyz/hw-wallet-cli-spec. The builders take the device as a
// digestSigner, so tests drive them with a software key.

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const attestKind = "tkey-self"

// digestSigner returns the device public key (X||Y) and the raw 64-byte (r||s) signature of digest.
type digestSigner func(digest []byte) (pubkey, rawSig []byte, err error)

func deviceSigner(cfg commonFlags) digestSigner {
	return func(digest []byte) ([]byte, []byte, error) { return signDigestWithSigner(cfg, digest) }
}

type addressOutput struct {
	Pubkey  string `json:"pubkey"`
	Address string `json:"address"`
}

func makeAddressOutput(pubkey []byte) (addressOutput, error) {
	addr, err := ethereumAddress(pubkey)
	if err != nil {
		return addressOutput{}, err
	}
	return addressOutput{Pubkey: "0x" + hex.EncodeToString(pubkey), Address: addr.Hex()}, nil
}

// signature27 is r || s || v with v = 27/28, what ecrecover and OpenZeppelin take. The
// internal 65-byte form from finalizeEthereumSignature keeps go-ethereum's v = 0/1.
func signature27(ethSig []byte) (string, error) {
	if len(ethSig) != 65 || ethSig[64] > 1 {
		return "", errors.New("expected a 65-byte signature with v = 0/1")
	}
	out := append([]byte{}, ethSig...)
	out[64] += 27
	return hexutil.Encode(out), nil
}

// signedDigest signs digest and returns the checked signature in go-ethereum form and its address.
func signedDigest(sign digestSigner, digest []byte) (signOutput, []byte, error) {
	pubkey, rawSig, err := sign(digest)
	if err != nil {
		return signOutput{}, nil, err
	}
	ethSig, addr, err := finalizeEthereumSignature(digest, pubkey, rawSig)
	if err != nil {
		return signOutput{}, nil, err
	}
	if err := verifyRecoveredSignature(digest, ethSig, addr); err != nil {
		return signOutput{}, nil, err
	}
	sig, err := signature27(ethSig)
	if err != nil {
		return signOutput{}, nil, err
	}
	return signOutput{Address: addr.Hex(), Digest: hexutil.Encode(digest), Signature: sig}, ethSig, nil
}

func makeDigestOutput(sign digestSigner, digest []byte) (signOutput, error) {
	out, _, err := signedDigest(sign, digest)
	return out, err
}

func makePersonalOutput(sign digestSigner, msg []byte) (signOutput, error) {
	hash, _ := accounts.TextAndHash(msg)
	return makeDigestOutput(sign, hash)
}

func makeTypedOutput(sign digestSigner, td apitypes.TypedData) (signTypedOutput, error) {
	hash, encoded, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		return signTypedOutput{}, err
	}
	out, err := makeDigestOutput(sign, hash)
	if err != nil {
		return signTypedOutput{}, err
	}
	// encoded is raw bytes (0x19 0x01 || domainSeparator || hashStruct); a Go string would be
	// mangled by JSON, so it goes out as hex.
	return signTypedOutput{Address: out.Address, Digest: out.Digest, Signature: out.Signature,
		Encoded: "0x" + hex.EncodeToString([]byte(encoded))}, nil
}

func makeTxOutput(sign digestSigner, tx *types.Transaction, signer types.Signer) (signTxOutput, error) {
	digest := signer.Hash(tx).Bytes()
	out, ethSig, err := signedDigest(sign, digest)
	if err != nil {
		return signTxOutput{}, err
	}
	signedTx, err := tx.WithSignature(signer, ethSig)
	if err != nil {
		return signTxOutput{}, err
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		return signTxOutput{}, err
	}
	recovered, err := types.Sender(signer, signedTx)
	if err != nil {
		return signTxOutput{}, err
	}
	if recovered.Hex() != out.Address {
		return signTxOutput{}, fmt.Errorf("recovered sender %s does not match signer %s", recovered.Hex(), out.Address)
	}
	return signTxOutput{Address: out.Address, Digest: out.Digest, Signature: out.Signature,
		RawTransaction: hexutil.Encode(rawTx), TxHash: signedTx.Hash().Hex()}, nil
}

type attestOutput struct {
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Cert    string `json:"cert"`
}

func makeAttestOutput(cert certificate, certPath string) attestOutput {
	return attestOutput{Kind: attestKind, Address: cert.WalletAddress, Cert: certPath}
}

type verifyOutput struct {
	Kind        string `json:"kind"`
	Address     string `json:"address"`
	Certificate string `json:"certificate"`
	Proof       string `json:"proof,omitempty"`
}

func makeVerifyOutput(cert certificate, proofChecked bool) verifyOutput {
	out := verifyOutput{Kind: attestKind, Address: cert.WalletAddress, Certificate: "ok"}
	if proofChecked {
		out.Proof = "ok"
	}
	return out
}
