# retroXt reskin — builds BOTH runtime libraries from the one shared source
# (retroXt.c).  The two WP builds are interposed differently, so the visibility
# differs:
#
#   WP 8.0  dynamically links X11/Xt -> retroXt interposes by SYMBOL (LD_PRELOAD,
#           or the installer's DT_NEEDED swap libX11.so.6->retroXt.so).  The X*/Xt*
#           hook functions MUST be EXPORTED, so NO -fvisibility=hidden here.
#
#   WP 8.1  statically links X11/Xt -> the hooks are reached by inline-detour at
#           fixed ADDRESSES (wp81port/), so the symbols are HIDDEN (built there).
#
# Cairo is dlopen'd at run time, so it is not linked.
CC   = gcc
XINC = -I/usr/include/cairo
XLIB = -Wl,--no-as-needed -l:libXt.so.6 -l:libX11.so.6 -ldl

all: retroXt.so wp81

retroXt.so: retroXt.c
	$(CC) -m32 -shared -fPIC -O2 $(XINC) -o $@ retroXt.c $(XLIB)

wp81:
	$(MAKE) -C wp81port retroXt81.so

clean:
	rm -f retroXt.so
	$(MAKE) -C wp81port clean

.PHONY: all wp81 clean
