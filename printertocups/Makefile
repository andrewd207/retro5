# printertocups — 32-bit (WP is i386). libcups is dlopen'd at runtime, not linked.
# SPDX-License-Identifier: MIT
CC      ?= gcc
CFLAGS  ?= -m32 -O2 -fPIC -Wall -Wextra -std=gnu99
LDFLAGS ?= -m32
LIBS    := -ldl -lpthread

SO   := printertocups.so
OBJ  := p2c.o

all: $(SO) p2c-test

$(SO): $(OBJ)
	$(CC) $(LDFLAGS) -shared -Wl,-soname,$(SO) -o $@ $(OBJ) $(LIBS)
	@echo "== built $(SO) (32-bit) =="

p2c.o: p2c.c p2c.h
	$(CC) $(CFLAGS) -c -o $@ p2c.c

# standalone test harness: links the object directly (no dlopen of ourselves)
p2c-test: p2c.c p2c.h test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ p2c.c test.c $(LIBS)

test: p2c-test
	./p2c-test list

clean:
	rm -f $(SO) $(OBJ) p2c-test

.PHONY: all test clean
