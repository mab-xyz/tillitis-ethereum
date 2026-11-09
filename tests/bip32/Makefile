# Native (host) test of the device BIP-32 core against the BIP-32 spec vectors.
P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
UP ?= $(P)/../../../research/upstream
MONO = $(UP)/tkey-libs/monocypher
UECC = $(UP)/tkey-fido2/crypto/micro-ecc

CFLAGS = -O2 -I $(MONO) -I $(UECC) -DuECC_PLATFORM=0
OURFLAGS = -Wall -Wextra -Werror

bip32_test: test_bip32.c $(P)/../../device/ethsign-hd/bip32.c $(P)/../../device/ethsign-hd/bip32.h
	$(CC) $(CFLAGS) -c -o uECC.o $(UECC)/uECC.c
	$(CC) $(CFLAGS) -c -o mono.o $(MONO)/monocypher.c
	$(CC) $(CFLAGS) -c -o mono-ed.o $(MONO)/monocypher-ed25519.c
	$(CC) $(CFLAGS) $(OURFLAGS) -o $@ test_bip32.c uECC.o mono.o mono-ed.o

HD = $(P)/../../device/ethsign-hd

keycache_test: test_keycache.c $(HD)/keycache.c $(HD)/keycache.h $(HD)/bip32.c $(HD)/bip32.h bip32_test
	$(CC) $(CFLAGS) $(OURFLAGS) -o $@ test_keycache.c $(HD)/keycache.c $(HD)/bip32.c uECC.o mono.o mono-ed.o

.PHONY: test
test: bip32_test keycache_test
	./bip32_test $(P)/vectors.txt
	./keycache_test
