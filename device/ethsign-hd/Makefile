# Build the BIP-32 HD Ethereum signer TKey app. Reuses device/ethsign's
# protocol helpers; device/ethsign itself is never rebuilt from here.

OBJCOPY ?= llvm-objcopy

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../../../research/upstream/tkey-libs
MICROECCDIR ?= $(P)/../../../research/upstream/tkey-fido2/crypto/micro-ecc
MONODIR = $(LIBDIR)/monocypher
LEGACY = $(P)/../ethsign

CC = clang

CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration -Wextra -Wshadow \
   -I $(LIBDIR)/include -I $(LIBDIR) -I $(P) -I $(LEGACY) -I $(MICROECCDIR) -I $(MONODIR)

ifneq ($(TKEY_ETH_APP_TOUCH),)
CFLAGS := $(CFLAGS) -DTKEY_ETH_APP_TOUCH
endif

LDFLAGS = -T $(LIBDIR)/app.lds -L $(LIBDIR) -lcommon -lcrt0

.PHONY: all
all: app.bin

%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

OBJS = main.o bip32.o app_proto.o uECC.o blake2s.o monocypher.o monocypher-ed25519.o

app.elf: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

main.o: main.c bip32.h $(LEGACY)/app_proto.h
bip32.o: bip32.c bip32.h
app_proto.o: $(LEGACY)/app_proto.c $(LEGACY)/app_proto.h
	$(CC) $(CFLAGS) -c -o $@ $<
uECC.o: $(MICROECCDIR)/uECC.c
	$(CC) $(CFLAGS) -DuECC_PLATFORM=0 -c -o $@ $<
blake2s.o: $(LIBDIR)/blake2s/blake2s.c
	$(CC) $(CFLAGS) -c -o $@ $<
monocypher.o: $(MONODIR)/monocypher.c
	$(CC) $(CFLAGS) -c -o $@ $<
monocypher-ed25519.o: $(MONODIR)/monocypher-ed25519.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f app.bin app.elf $(OBJS)
