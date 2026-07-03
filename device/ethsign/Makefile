# Build a minimal TKey device app that derives a secp256k1 key from the CDI
# and signs Ethereum digests.

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	shasum = shasum -a 512
else
	shasum = sha512sum
endif

OBJCOPY ?= llvm-objcopy

P := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
LIBDIR ?= $(P)/../../../research/upstream/tkey-libs
MICROECCDIR ?= $(P)/../../../research/upstream/tkey-fido2/crypto/micro-ecc

CC = clang

INCLUDE = $(LIBDIR)/include

CFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany \
   -static -std=gnu99 -O2 -ffast-math -fno-common -fno-builtin-printf \
   -fno-builtin-putchar -nostdlib -mno-relax -flto -g \
   -Wall -Werror=implicit-function-declaration -Wextra -Wshadow \
   -I $(INCLUDE) -I $(LIBDIR) -I $(P) -I $(MICROECCDIR)

ifneq ($(TKEY_ETH_APP_TOUCH),)
CFLAGS := $(CFLAGS) -DTKEY_ETH_APP_TOUCH
endif

AS = clang
ASFLAGS = -target riscv32-unknown-none-elf -march=rv32iczmmul -mabi=ilp32 -mcmodel=medany -mno-relax

LDFLAGS = -T $(LIBDIR)/app.lds -L $(LIBDIR) -lcommon -lcrt0

.PHONY: all
all: app.bin

%.bin: %.elf
	$(OBJCOPY) --input-target=elf32-littleriscv --output-target=binary $^ $@
	chmod a-x $@

OBJS = main.o app_proto.o $(MICROECCDIR)/uECC.o $(LIBDIR)/blake2s/blake2s.o

app.elf: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

main.o: main.c app_proto.h platform.h
app_proto.o: app_proto.c app_proto.h platform.h
$(MICROECCDIR)/uECC.o: $(MICROECCDIR)/uECC.c
	$(CC) $(CFLAGS) -DuECC_PLATFORM=0 -c -o $@ $<
$(LIBDIR)/blake2s/blake2s.o: $(LIBDIR)/blake2s/blake2s.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f app.bin app.elf main.o app_proto.o \
		$(MICROECCDIR)/uECC.o \
		$(LIBDIR)/blake2s/blake2s.o
