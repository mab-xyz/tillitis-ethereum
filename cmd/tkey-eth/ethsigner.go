package main

import (
	"fmt"

	"github.com/tillitis/tkeyclient"
)

var (
	cmdGetPubkey      = appCmd{0x01, "cmdGetPubkey", tkeyclient.CmdLen1}
	rspGetPubkey      = appCmd{0x02, "rspGetPubkey", tkeyclient.CmdLen128}
	cmdSignDigest     = appCmd{0x03, "cmdSignDigest", tkeyclient.CmdLen128}
	rspSignDigest     = appCmd{0x04, "rspSignDigest", tkeyclient.CmdLen128}
	cmdGetNameVersion = appCmd{0x05, "cmdGetNameVersion", tkeyclient.CmdLen1}
	rspGetNameVersion = appCmd{0x06, "rspGetNameVersion", tkeyclient.CmdLen32}
	cmdGetAppDigest   = appCmd{0x07, "cmdGetAppDigest", tkeyclient.CmdLen1}
	rspGetAppDigest   = appCmd{0x08, "rspGetAppDigest", tkeyclient.CmdLen128}
)

type appCmd struct {
	code   byte
	name   string
	cmdLen tkeyclient.CmdLen
}

func (c appCmd) Code() byte                    { return c.code }
func (c appCmd) CmdLen() tkeyclient.CmdLen     { return c.cmdLen }
func (c appCmd) Endpoint() tkeyclient.Endpoint { return tkeyclient.DestApp }
func (c appCmd) String() string                { return c.name }

type ethSigner struct {
	tk *tkeyclient.TillitisKey
}

func newEthSigner(tk *tkeyclient.TillitisKey) ethSigner {
	return ethSigner{tk: tk}
}

func (s ethSigner) GetAppNameVersion() (*tkeyclient.NameVersion, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetNameVersion, id)
	if err != nil {
		return nil, err
	}
	if err := s.tk.Write(tx); err != nil {
		return nil, err
	}
	s.tk.SetReadTimeoutNoErr(2)
	defer s.tk.SetReadTimeoutNoErr(0)
	rx, _, err := s.tk.ReadFrame(rspGetNameVersion, id)
	if err != nil {
		return nil, err
	}
	nameVer := &tkeyclient.NameVersion{}
	nameVer.Unpack(rx[2:])
	return nameVer, nil
}

func (s ethSigner) GetPubkey() ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetPubkey, id)
	if err != nil {
		return nil, err
	}
	if err := s.tk.Write(tx); err != nil {
		return nil, err
	}
	rx, _, err := s.tk.ReadFrame(rspGetPubkey, id)
	if err != nil {
		return nil, err
	}
	return append([]byte{}, rx[2:2+64]...), nil
}

func (s ethSigner) GetAppDigest() ([]byte, error) {
	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdGetAppDigest, id)
	if err != nil {
		return nil, err
	}
	if err := s.tk.Write(tx); err != nil {
		return nil, err
	}
	rx, _, err := s.tk.ReadFrame(rspGetAppDigest, id)
	if err != nil {
		return nil, err
	}
	return append([]byte{}, rx[2:2+32]...), nil
}

func (s ethSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("expected 32-byte digest, got %d", len(digest))
	}

	id := 2
	tx, err := tkeyclient.NewFrameBuf(cmdSignDigest, id)
	if err != nil {
		return nil, err
	}
	copy(tx[2:], digest)
	if err := s.tk.Write(tx); err != nil {
		return nil, err
	}
	rx, _, err := s.tk.ReadFrame(rspSignDigest, id)
	if err != nil {
		return nil, err
	}
	if rx[2] != tkeyclient.StatusOK {
		return nil, fmt.Errorf("sign failed")
	}
	return append([]byte{}, rx[3:3+64]...), nil
}
