# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines

# retro5 - libc5 -> glibc shim for WordPerfect 8 (Linux)
#
#   make            build retro5.so (32-bit)
#   make check      report which of wpinstg's 115 libc syms we still miss
#   make patch      copy $(WPBIN) -> build/, retarget it to this shim via patchelf
#   make clean

CC        := gcc
# 9-char name == len("libc.so.5") so DT_NEEDED can be swapped IN PLACE.
# patchelf grows .dynstr and corrupts the ancient .hash (loader SIGFPEs on
# nbuckets==0), so we do same-length byte edits instead — nothing moves.
SONAME    := retro5.so
TARGET    := retro5.so
CFLAGS    := -m32 -fPIC -O2 -Wall -Wno-unused-parameter -fno-stack-protector
LDFLAGS   := -m32 -shared -Wl,-soname,$(SONAME) -Wl,--hash-style=both -ldl

SRC_C     := $(wildcard src/*.c)
SRC_S     := $(wildcard src/*.S)
OBJ       := $(SRC_C:.c=.o) $(SRC_S:.S=.o)

# retarget config (override on the command line)
WPBIN     ?= ../linux/ins/wpinstg
GLIBC_LD  ?= /lib/ld-linux.so.2
# install retro5.so where the 32-bit dynamic loader looks by DEFAULT (a trusted
# multiarch dir) so retargeted binaries need no LD_LIBRARY_PATH. Override LIBDIR
# for a non-multiarch layout, or DESTDIR for staged/packaged installs.
DESTDIR   ?=
LIBDIR    ?= /usr/lib/i386-linux-gnu

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)
	@echo "== built $@ =="
	@readelf -d $@ 2>/dev/null | grep -i soname || true
	@echo "exported symbols: $$(readelf --dyn-syms $@ | awk '$$4=="FUNC"||$$4=="OBJECT"{print $$8}' | grep -v '^$$' | sort -u | wc -l)"

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@
src/%.o: src/%.S
	$(CC) $(CFLAGS) -c $< -o $@

# Which of wpinstg's 115 libc symbols do we still not export?
check: $(TARGET)
	@readelf --dyn-syms $(WPBIN) 2>/dev/null | awk '$$7=="UND"&&$$8{print $$8}' | sort -u > /tmp/_need.txt
	@readelf --dyn-syms /usr/i386-compat-gnulibc1/lib/libc.so.5 2>/dev/null | awk '$$7!="UND"&&$$8{print $$8}' | sort -u > /tmp/_libc5.txt
	@comm -12 /tmp/_need.txt /tmp/_libc5.txt > /tmp/_libcneed.txt
	@readelf --dyn-syms $(TARGET) 2>/dev/null | awk '$$4=="FUNC"||$$4=="OBJECT"{print $$8}' | sort -u > /tmp/_have.txt
	@echo "libc symbols needed: $$(wc -l < /tmp/_libcneed.txt)"
	@echo "still MISSING:"; comm -23 /tmp/_libcneed.txt /tmp/_have.txt | sed 's/^/  /' || echo "  (none)"

# Copy the target binary and retarget it to the glibc world + this shim,
# using SAME-LENGTH in-place byte edits (no section movement, .hash intact).
patch: $(TARGET)
	@mkdir -p build
	install -m755 $(WPBIN) build/$(notdir $(WPBIN))
	cp $(TARGET) build/
	python3 -c "import sys; f='build/$(notdir $(WPBIN))'; d=open(f,'rb').read(); \
d=d.replace(b'/lib/ld-linux.so.1\x00',b'/lib/ld-linux.so.2\x00'); \
d=d.replace(b'libc.so.5\x00',b'retro5.so\x00'); \
d=d.replace(b'libm.so.5\x00',b'libm.so.6\x00'); \
open(f,'wb').write(d); print('patched (in-place, same-length)')"
	python3 hidesym.py build/$(notdir $(WPBIN)) errno
	@echo "== retargeted build/$(notdir $(WPBIN)) =="
	@readelf -l build/$(notdir $(WPBIN)) 2>/dev/null | grep -i interpreter
	@readelf -d build/$(notdir $(WPBIN)) 2>/dev/null | awk -F'[][]' '/NEEDED/{print "  "$$2}'

# install the shim into a loader-default 32-bit dir + refresh the cache.
# Run as root (sudo make install). One copy serves every retargeted binary.
install: $(TARGET)
	install -d $(DESTDIR)$(LIBDIR)
	install -m644 $(TARGET) $(DESTDIR)$(LIBDIR)/$(TARGET)
	-ldconfig
	@echo "== installed $(TARGET) -> $(DESTDIR)$(LIBDIR)/ (no LD_LIBRARY_PATH needed) =="

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(TARGET)
	-ldconfig
	@echo "== removed $(LIBDIR)/$(TARGET) =="

clean:
	rm -f $(OBJ) $(TARGET)
	rm -rf build

.PHONY: all check patch install uninstall clean
