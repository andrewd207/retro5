# wpprint-sink — modern WordPerfect 8 print subsystem replacement
CC     ?= cc
CFLAGS ?= -O2 -Wall -Wextra

LIB = wpproto.c wpdest.c wpexec.c wpcups.c

all: wpsink wpselect

wpsink: wpsink.c $(LIB) wpproto.h wpdest.h wpexec.h
	$(CC) $(CFLAGS) -o $@ wpsink.c $(LIB)

t_tests: tests.c $(LIB) wpdest.h wpexec.h wpproto.h
	$(CC) $(CFLAGS) -o $@ tests.c $(LIB)

.PHONY: test clean
test: wpsink t_tests
	./t_tests
	./wpsink --selftest

clean:
	rm -f wpsink wpselect t_tests /tmp/wpsink-selftest.ps

wpselect: wpselect.c $(LIB) wpcups.h
	$(CC) $(CFLAGS) -o $@ wpselect.c $(LIB)
