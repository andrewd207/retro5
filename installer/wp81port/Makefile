# WP 8.1 static-function detour port.
CC      = gcc
CFLAGS  = -m32 -fPIC -O2 -Wall
XINC    = -I/usr/include/cairo

all: retroXt81.so detour_selftest

# the port shim: retroXt81.c is `#define RX_STATIC81` + #include "../retroXt.c",
# so it compiles the SAME hook bodies as 8.0 but reaches the originals through the
# inline-detour trampolines.  -fvisibility=hidden keeps the hook symbols out of the
# dynamic table.
#
# CRUCIAL: we do NOT link modern libX11/libXt.  On 8.1 xwp STATICALLY links its own
# Xlib/Xt/Motif and owns the Display + widget tree; a modern 2nd instance driving that
# same Display crashes (_XReply/_XSend SIGSEGV -- proven live).  rx81_shim.o instead
# tail-jumps every X/Xt helper retroXt calls into xwp's OWN static Xlib (byte-exact
# addresses from the XFree86 3.3.2 map), so ALL X traffic stays in the single static
# instance.  Rendering uses cairo IMAGE surfaces committed via XPutImage (detoured to
# static) -- never a cairo xlib surface (that would pull modern libX11 onto the Display).
retroXt81.so: retroXt81.c ../retroXt.c detour81.c detour81.h wp81_detours.h rx81_shim.o \
              wp81_fpguard.c wp81_fingerprint.h
	$(CC) -m32 -shared -fPIC -fvisibility=hidden -O2 -DRX_STATIC81 $(XINC) \
	    -o $@ retroXt81.c detour81.c wp81_fpguard.c rx81_shim.o -ldl

# helper-routing shim: X/Xt calls -> xwp's static Xlib addresses. Regenerate with
# scratchpad/gen_rx81_shim.py if the mapped addresses change.
rx81_shim.o: rx81_shim.s
	as --32 -o $@ rx81_shim.s

# proves the detour engine end-to-end (hook fires + original still callable)
detour_selftest: detour_selftest.c detour81.c detour81.h
	$(CC) $(CFLAGS) -o $@ detour_selftest.c detour81.c

# regenerate wp81_detours.h + the symbol map from the xwp binary (needs capstone+pyelftools)
regen:
	python3 patch81.py

test: detour_selftest
	./detour_selftest

clean:
	rm -f retroXt81.so rx81_shim.o detour_selftest mock_prog mock_preload.so

.PHONY: all regen test clean
