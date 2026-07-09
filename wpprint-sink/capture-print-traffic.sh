#!/bin/sh
# SPDX-License-Identifier: MIT
# capture-print-traffic.sh — record the EXACT bytes WordPerfect exchanges with
# its print helpers, to validate/complete the RE'd protocol (docs/print-ipc-
# protocol.md) before/while implementing the modern sink.
#
#   ./capture-print-traffic.sh /path/to/xwp-launcher   # then print a page in WP
#
# It straces xwp AND its children (-f), keeping only the calls that carry the
# print IPC — socket/connect/bind/accept + the read/write/open on the $WPCOM
# "wpc-*" / ".wpexc*" rendezvous — with full buffer contents (-s 4096 -xx), so
# you can read the handshake, the e_job/e_device/e_print framing, and the job
# body byte-for-byte. Output: ./print-trace.<pid>.log
#
# Requires: strace (sudo apt install strace). Run it, then in WP do File>Print.
set -eu

LAUNCH="${1:-}"
[ -n "$LAUNCH" ] || { echo "usage: $0 /path/to/xwp-launcher (e.g. ~/.local/bin/xwp-8.1)"; exit 2; }
command -v strace >/dev/null 2>&1 || { echo "strace not found (sudo apt install strace)"; exit 1; }

OUT="./print-trace.$$.log"
echo "== capturing to $OUT =="
echo "   Launch WordPerfect, open/type a doc, and File > Print. Then close WP."
echo "   Watch the print IPC: e_wpexc1 handshake, e_job/e_device/e_print, job body."
echo

# -f follow children (xwpdest/wpexc/xwppmgr); -yy annotate fds with the socket/
# file they point at; -s 4096 -xx full byte dumps; trace only the IPC-bearing calls.
exec strace -f -yy -s 4096 -xx -tt \
    -e trace=socket,connect,bind,accept,accept4,listen,read,write,open,openat,unlink,mkfifo,execve \
    -o "$OUT" \
    "$LAUNCH"
