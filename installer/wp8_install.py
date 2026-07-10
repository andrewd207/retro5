#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""wp8_install.py - zero-to-installed engine for WordPerfect 8 (Linux) on modern
systems, using the raw Corel media + the retro5.so libc5->glibc shim.

USER-LOCAL, NO ROOT REQUIRED. Everything lands under a user-writable root
(default ~/.local/share/wordperfect8); the launcher points WPC/LD_LIBRARY_PATH
there. The only optional root bit is /etc/printcap (skipped if unavailable).

Pipeline (mirrors retro5/build-tree.sh, with the gaps we found fixed):
  1. prerequisites  - media, 32-bit loader, gcc; build wpdecom2 + retro5.so
  2. install tree   - parse shared/ship, decompress/copy every entry incl.
                      prn/gu printer drivers (build-tree.sh skipped those)
  3. retarget       - ld.so.1->2, libc.so.5->retro5.so, libm.so.5->6, hide errno
  4. patches        - guarded morpher typing-crash fix (only the original bytes)
  5. permissions    - 0400 -> 0600 (WP probes config files R_OK|W_OK)
  6. runtime config - shim into shbin10; VALID empty .wpc.admin; wplib markers
  7. launcher       - ~/.local/bin/xwp wrapper (+ .desktop); XLOCALEDIR fix
  8. per-user setup - seed ~/.wprc/.wpc8x.set so first-run doesn't error

The engine is UI-agnostic: run() is a generator yielding Step objects the GUI
(or the CLI) renders. Nothing here imports GTK.
"""
from __future__ import annotations
import filecmp, fnmatch, os, re, shutil, stat, struct, subprocess, sys
from dataclasses import dataclass, field
from pathlib import Path

# This repo ships the tooling (shim + decompressor); the *media* is the user's
# own Corel disc/ISO and is kept strictly separate from it.
TOOLING        = Path(__file__).resolve().parent.parent      # repo root
# side-by-side installs live under a base dir + a version subdir (8.0 / 8.1)
DEFAULT_BASE   = Path.home() / ".local/share/wordperfect"
DEFAULT_TARGET = Path.home() / ".local/share/wordperfect8"   # engine fallback
GLOBAL_BASE    = Path("/opt/wordperfect")                    # global install base (run as root)


def default_base():
    """Where side-by-side installs go when no --target is given. Run as root we
    install GLOBALLY under /opt (usable by every user, world-readable, system
    launcher) instead of hiding it in /root/.local; otherwise per-user ~/.local."""
    return GLOBAL_BASE if os.geteuid() == 0 else DEFAULT_BASE

# morpher typing-crash patch: NOP the dead OOB `call strcpy` in mor_read_entry
# (the unguarded `byte & 0x7f` index into the 43-entry particle table). Each
# entry is (file offset, original bytes guard, NOP replacement) for one known
# xwp build; every entry is byte-guarded, so only the matching build is touched.
# Add a line here when a new build's signature is located. Find it by: locate
# the particle-table base (pointers to "about"/"above"/…/"without"), find the
# three `mov TABLE(,%eax,4),%eax` sites, and patch the one whose index is NOT
# preceded by `cmp $0x2a; jg` and which feeds `strcpy` (the other two guard + strcat).
#
# WHY IT'S FATAL ON THE PORT BUT WAS LATENT ON 1998 libc5 (best-guess root cause):
# This is a data-dependent out-of-bounds *read*, not a write. For idx > 0x2a,
# table[idx] fetches 4 bytes from the buffer sitting just past the table and
# hands them to strcpy AS THE SOURCE POINTER. The crash we caught had
# src = 0x64646464 = "dddd" — the user's own keystrokes reinterpreted as an
# address. Whether strcpy faults therefore depends solely on whether that stray
# pointer happens to point at mapped, readable memory:
#   * Original static-libc5 binary (fixed Linux-2.0 address space, one malloc,
#     no ASLR): the adjacent slot dereferenced to readable memory, so the errant
#     strcpy copied a few bytes of garbage into a *dead* stack buffer and nothing
#     ever faulted -> the bug shipped invisibly and survived ~25 years.
#   * Modern glibc + retro5: different heap/arena placement, different mmap base
#     + ASLR, and different adjacent buffer contents, so the stray pointer now
#     lands on an unmapped page -> SIGSEGV the moment the as-you-type morphology
#     path runs on a triggering word.
# It is NOT a shim defect: we verified the .mor `fread` is byte-identical to the
# file, so the index values are unchanged — only the memory environment the
# stray pointer is interpreted against changed, which is exactly what a
# libc5->glibc port changes. The strcpy dst is write-only dead code, so NOPing
# the call is behavior-neutral. Classic latent memory-safety bug, unmasked by
# the port rather than introduced by it.
MORPH_PATCHES = [
    (0x1e8dda, bytes.fromhex("e82997e1ff"), bytes.fromhex("9090909090")),  # 8.16MB static-X build
    (0x211cff, bytes.fromhex("e8fc53dfff"), bytes.fromhex("9090909090")),  # 8.0.0076 dynamic-X build
]


@dataclass
class Step:
    key: str
    title: str
    fraction: float          # overall progress 0..1 after this step
    detail: str = ""
    ok: bool = True
    log: list[str] = field(default_factory=list)


class InstallError(Exception):
    pass


class Engine:
    def __init__(self, media: Path, target: Path = DEFAULT_TARGET,
                 make_launcher: bool = True, make_desktop: bool = True,
                 tree_only: bool = False, tooling: Path = TOOLING,
                 version: str = "8", source_kind: str = "native",
                 install_deps: bool = False, overwrite: bool = False):
        self.media = Path(media)            # a resolved native tree OR .deb wp tree
        self.target = Path(target)
        self.tooling = Path(tooling)
        self.version = str(version)         # "8.0" / "8.1" — side-by-side installs
        self.source_kind = source_kind      # "native" (ship manifest) or "deb"
        self.install_deps = install_deps    # --install-deps: pull the 32-bit runtime
        self.overwrite = overwrite          # --overwrite: install over an existing tree
        self.compat = self.tooling / "retro5"           # shim source (this repo)
        self.wpdecom_src = self.tooling / "tools/wpdecom2.c"
        self.wpdecom = self.tooling / "tools/wpdecom2"  # build output (gitignored)
        self.retro5 = self.compat / "retro5.so"         # prebuilt or built
        self.make_launcher = make_launcher
        self.make_desktop = make_desktop                # app-menu entry (optional)
        # tree_only: install the tree + retarget + patch + config, but NOT the
        # per-user launcher/~/.wprc (used for the root half of a system install;
        # the per-user half runs unprivileged afterward).
        self.tree_only = tree_only
        self.stats = {}

    # ---- helpers ---------------------------------------------------------
    @staticmethod
    def _u16(p): return p[0] | (p[1] << 8)

    def _run(self, args, **kw):
        return subprocess.run(args, capture_output=True, text=True, **kw)

    def _is_elf32(self, f: Path) -> bool:
        try:
            with open(f, "rb") as fh:
                h = fh.read(5)
            return h[:4] == b"\x7fELF" and h[4] == 1
        except Exception:
            return False

    # ---- safety guard: don't clobber an existing install ----------------
    def _guard_target(self) -> list[str]:
        """Refuse to install onto an existing non-empty target unless
        --overwrite. A fresh install writes files in place with no backup, so
        pointing it at an install you already have (or any populated dir) would
        silently overwrite name-collisions. --complete/--uninstall never call
        this. Returns a one-line warning when --overwrite bypasses the guard."""
        t = self.target
        if not t.exists():
            return []
        if not self.overwrite:
            if t.is_dir():
                if not any(t.iterdir()):
                    return []                       # empty dir is fine
                what = "directory already exists and is not empty"
            else:
                what = "path already exists and is not a directory"
            raise InstallError(
                f"target {what}: {t}\n"
                "        Refusing to overwrite it (existing files would be "
                "replaced in place, no backup).\n"
                "        Re-run with --overwrite to install over it, or pass a "
                "different --target.\n"
                f"        To remove an old install cleanly first: --uninstall {t}")
        # --overwrite: allowed, but say so loudly.
        if t.is_dir() and any(t.iterdir()):
            return [f"WARNING: --overwrite: installing over existing tree at {t} "
                    "(files with the same names are replaced in place, no backup)"]
        return []

    # ---- 32-bit runtime deps (optional, --install-deps) -----------------
    def _install_deps(self) -> list[str]:
        """Detect the system package manager and install the 32-bit runtime
        libraries WordPerfect needs: the i386 glibc (always) plus the 32-bit X
        libs — some bundled binaries link X dynamically even in the 'static-X'
        editions, so we install them too. Requires root."""
        if os.geteuid() != 0:
            raise InstallError("--install-deps installs system packages; re-run as root (sudo)")
        apt = shutil.which("apt-get"); dnf = shutil.which("dnf")
        pac = shutil.which("pacman");  zyp = shutil.which("zypper")
        print("==> installing system packages (this can take a few minutes)…", flush=True)

        def run(cmd, fatal=True):
            # STREAM the package manager's output live (do NOT capture) so the user
            # sees progress — a captured apt-get sits silent for minutes and looks
            # hung. Echo the command first for context.
            print("   $ " + " ".join(cmd), flush=True)
            r = subprocess.run(cmd)
            if r.returncode != 0 and fatal:
                raise InstallError("package install failed: " + " ".join(cmd))
            return r.returncode

        if apt:
            run(["dpkg", "--add-architecture", "i386"])
            run(["apt-get", "update"])
            run(["apt-get", "install", "-y", "libc6:i386"])
            # libxt6 was renamed libxt6t64 on Ubuntu 24.04+/Debian 13 (time_t)
            if run(["apt-get", "install", "-y",
                    "libx11-6:i386", "libxpm4:i386", "libxt6:i386"], fatal=False) != 0:
                run(["apt-get", "install", "-y",
                     "libx11-6:i386", "libxpm4:i386", "libxt6t64:i386"])
            # printing: xwpdest execs lp/lpr, so a fresh box (esp. a headless VM)
            # needs the CUPS client tools or WP has nothing to spool to. Native,
            # not i386. Non-fatal — don't abort a WP install over the print client.
            run(["apt-get", "install", "-y", "cups-bsd", "cups-client"], fatal=False)
            # UI fonts: WP's Motif menus request -adobe-helvetica-*-75-75-iso8859-1.
            # A fresh box without the legacy X bitmap fonts can't resolve it and
            # falls back to an ugly `fixed` font. Pull the adobe-helvetica providers.
            run(["apt-get", "install", "-y", "xfonts-base", "xfonts-75dpi",
                 "xfonts-100dpi", "xfonts-scalable"], fatal=False)
            return ["installed 32-bit runtime + CUPS client + X UI fonts via apt"]
        if dnf:
            run(["dnf", "install", "-y", "glibc.i686",
                 "libX11.i686", "libXpm.i686", "libXt.i686"])
            run(["dnf", "install", "-y", "cups-client"], fatal=False)
            run(["dnf", "install", "-y", "xorg-x11-fonts-75dpi",
                 "xorg-x11-fonts-100dpi", "xorg-x11-fonts-ISO8859-1-75dpi"], fatal=False)
            return ["installed 32-bit runtime + CUPS client + X UI fonts via dnf"]
        if pac:
            run(["pacman", "-S", "--needed", "--noconfirm",
                 "lib32-glibc", "lib32-libx11", "lib32-libxpm", "lib32-libxt"])
            run(["pacman", "-S", "--needed", "--noconfirm", "cups"], fatal=False)
            run(["pacman", "-S", "--needed", "--noconfirm",
                 "xorg-fonts-75dpi", "xorg-fonts-100dpi"], fatal=False)
            return ["installed 32-bit runtime + CUPS client + X UI fonts via pacman (needs [multilib])"]
        if zyp:
            run(["zypper", "--non-interactive", "install", "glibc-32bit",
                 "libX11-6-32bit", "libXpm4-32bit", "libXt6-32bit"])
            run(["zypper", "--non-interactive", "install", "cups-client"], fatal=False)
            run(["zypper", "--non-interactive", "install",
                 "xorg-x11-fonts", "xorg-x11-fonts-legacy"], fatal=False)
            return ["installed 32-bit runtime + CUPS client + X UI fonts via zypper"]
        raise InstallError("no supported package manager (apt/dnf/pacman/zypper) found; "
                           "install the 32-bit libs manually (see the README)")

    # ---- step 1: prerequisites ------------------------------------------
    def prereqs(self) -> list[str]:
        log = []
        log += self._guard_target()          # bail before touching anything
        if self.install_deps:
            # a package-install failure (no network, held package, …) must NOT
            # abort the whole install — the tree install + retarget don't need
            # the packages; WP just won't run/print until they're added. Warn.
            try:
                log += self._install_deps()
            except InstallError as e:
                log.append(f"WARNING: could not install dependencies ({e}); "
                           "continuing — install them by hand to run WordPerfect.")
        if not (self.media / "shared/ship").is_file():
            raise InstallError(f"install media not found (no shared/ship) at {self.media}")
        if not (self.media / "linux/bin").is_dir():
            raise InstallError(f"install media incomplete (no linux/ tree) at {self.media}")
        if not Path("/lib/ld-linux.so.2").exists():
            # needed to *run* WP, not to install it — warn, don't abort.
            log.append("WARNING: the 32-bit loader /lib/ld-linux.so.2 is missing — "
                       "WordPerfect won't start until you install it (Debian/Ubuntu: "
                       "sudo dpkg --add-architecture i386 && sudo apt install libc6:i386). "
                       "Installing the tree anyway.")
        # printing needs lp/lpr on PATH (WP's xwpdest execs them). Soft-warn — a
        # fresh/headless box often lacks the CUPS client; without it WP installs
        # and runs fine but can't print. --install-deps installs these for you.
        if not (shutil.which("lp") or shutil.which("lpr")):
            log.append("note: no 'lp'/'lpr' found — WordPerfect can't print until a "
                       "CUPS client is installed (Debian/Ubuntu: cups-bsd cups-client; "
                       "Fedora/openSUSE: cups-client; Arch: cups). Or re-run with "
                       "--install-deps.")
        # build wpdecom2 if needed
        if not (self.wpdecom.exists() and os.access(self.wpdecom, os.X_OK)):
            if not shutil.which("gcc"):
                raise InstallError("gcc not found (needed to build wpdecom2)")
            if not self.wpdecom_src.is_file():
                raise InstallError(f"decompressor source missing: {self.wpdecom_src}")
            r = self._run(["gcc", "-O2", "-w", "-o", str(self.wpdecom),
                           str(self.wpdecom_src)])
            if r.returncode != 0:
                raise InstallError("failed to build wpdecom2:\n" + r.stderr)
            log.append("built wpdecom2")
        else:
            log.append("wpdecom2 present")
        # ensure the shim exists (prefer prebuilt; else try the compat Makefile)
        if not self.retro5.exists():
            alt = self.compat / "build/retro5.so"
            if alt.exists():
                self.retro5 = alt
            elif (self.compat / "Makefile").exists():
                r = self._run(["make", "-C", str(self.compat)])
                if r.returncode != 0 or not self.retro5.exists():
                    raise InstallError("failed to build retro5.so:\n" + r.stderr)
                log.append("built retro5.so")
            else:
                raise InstallError("retro5.so not found and cannot build it")
        log.append(f"shim: {self.retro5}")
        return log

    # ---- step 2: install tree from ship manifest ------------------------
    @staticmethod
    def extract_wxar(data: bytes, dstdir: Path, perm: str) -> int:
        """Unpack a WP 'wxar' archive: repeated  <name>\\n<size>\\n<size bytes>.
        This is how the native installer (install.wp type 'a') lays down the
        PostScript fonts (archpfb/archafm) and BDF/PCF fonts. Returns count."""
        i, n = 0, 0
        try:
            mode = int(perm, 8) | 0o600
        except ValueError:
            mode = 0o644
        while i < len(data):
            nl = data.find(b"\n", i)
            if nl < 0:
                break
            name = data[i:nl].decode("latin1").strip(); i = nl + 1
            sl = data.find(b"\n", i)
            if sl < 0:
                break
            try:
                size = int(data[i:sl])
            except ValueError:
                break
            i = sl + 1
            chunk = data[i:i + size]; i += size
            if not name or "/" in name or name.startswith(".."):
                continue
            (dstdir / name).write_bytes(chunk)
            os.chmod(dstdir / name, mode)
            n += 1
        return n

    def _archive_bytes(self, src: Path):
        """Return an archive's bytes, decompressed by wpdecom2 if compressed,
        raw if not (rc==2), or None on failure. Shared by install + complete."""
        import tempfile
        fd, tmp = tempfile.mkstemp(prefix="wpdec_"); os.close(fd)
        try:
            r = self._run([str(self.wpdecom), str(src), tmp])
            if r.returncode == 2:
                return src.read_bytes()
            if r.returncode == 0 and os.path.getsize(tmp) > 0:
                return Path(tmp).read_bytes()
            return None
        finally:
            try: os.unlink(tmp)
            except OSError: pass

    def _install_supplementary_fonts(self, shlib: Path) -> int:
        """Copy the WP-named faces from the media's standalone fonts/ dir
        (verbatim); don't clobber archpfb members already present."""
        n = 0
        fdir = self.media / "fonts"
        if fdir.is_dir():
            for f in fdir.iterdir():
                if (f.is_file() and f.name.lower().startswith("wp")
                        and f.name.lower().endswith((".pfb", ".afm"))
                        and not (shlib / f.name).exists()):
                    shutil.copyfile(f, shlib / f.name)
                    os.chmod(shlib / f.name, 0o644); n += 1
        return n

    # WP runtime resources it resolves from shlib10, and where each is used.
    # Fonts: wp.drs lists a graphic font only if its .pfb outline (+ .afm
    #   metrics) is in shlib10.
    # Printer drivers: xwppmgr enumerates wp60????.??.all in shlib10.
    # Printer resources: .prs (passpost/pssave/…) loaded by name.
    # A retail disc drops all of these in shlib10 directly; the Corel .deb keeps
    # some in the tree but stashes others outside it (e.g. the fonts under
    # usr/X11R6/lib/X11/fonts/Type1/), so a bare tree-copy is incomplete —
    # famously the document font list then shows only Courier-WP.
    _SHLIB_RESOURCE_GLOBS = ("wp*.pfb", "wp*.afm", "wp60*.all", "*.prs")

    def _harvest_shlib_resources(self, shlib: Path) -> int:
        """Gather WP's shlib10 runtime resources (graphic fonts, printer drivers,
        printer .prs) from anywhere in the extracted media into shlib10, no
        matter how the media lays them out. Copies only names shlib10 is missing
        (never clobbers a file already in the WP tree). Case-insensitive; stays
        correct if a future .deb/disc moves these files around. Returns count."""
        # Scan from the top of the extracted media: the .deb tree is
        # <root>/usr/lib/wp8, and the split-out fonts live at <root>/usr/X11R6/…,
        # so climb from the wp tree until we reach the dir that CONTAINS usr/
        # (the extraction root). Guard against climbing all the way to the
        # filesystem root (which also "contains" /usr) — never scan there; fall
        # back to the media dir if there is no sane enclosing 'usr'.
        root, cur = self.media, self.media
        for _ in range(6):
            if cur.parent == cur:                # hit filesystem root — stop
                break
            if (cur / "usr").is_dir():
                root = cur; break
            cur = cur.parent
        seen, n = set(), 0
        for f in root.rglob("*"):
            if not f.is_file():
                continue
            low = f.name.lower()
            if not any(fnmatch.fnmatch(low, g) for g in self._SHLIB_RESOURCE_GLOBS):
                continue
            if low in seen:                      # first match by basename wins
                continue
            seen.add(low)
            dst = shlib / low
            if dst.exists():                     # already in the WP tree — keep it
                continue
            self._replace_copy(f, dst); os.chmod(dst, 0o644); n += 1
        return n

    def _ship_entries(self):
        """Yield (src, dst_rel_dir, dst_name, perm, opt) for linux + ALL sections."""
        txt = (self.media / "shared/ship").read_text(errors="replace").splitlines()
        keep, section = [], None
        for line in txt:
            s = line.strip()
            m = re.match(r"#ifdef\s+(\S+)", s)
            if m:
                section = m.group(1); continue
            if s.startswith("#endif"):
                section = None; continue
            if section not in ("linux", "ALL"):
                continue
            if not s or s.startswith("#"):
                continue
            keep.append(line)
        for line in keep:
            f = line.split()
            if len(f) < 7:
                continue
            _j, nam1, dir1, opt, perm, dir2, nam2 = f[0], f[1], f[2], f[3], f[4], f[5], f[6]
            src = self.media / "linux" / dir1 / nam1
            yield src, dir2, nam2, perm, opt

    def install_tree(self):
        dec = cp = miss = arch = extracted = 0
        for src, dir2, nam2, perm, opt in self._ship_entries():
            if not src.is_file():
                miss += 1; continue
            dstdir = self.target / dir2
            dstdir.mkdir(parents=True, exist_ok=True)
            typ = opt[-1] if len(opt) == 3 else "c"

            # 'a' = archive: obtain the (maybe compressed) archive, then wxar-
            # extract its members into dstdir. This is where the PostScript
            # fonts (archpfb/archafm) and BDF/PCF fonts actually come from.
            if typ == "a":
                data = self._archive_bytes(src)
                if data is None:
                    miss += 1; continue
                extracted += self.extract_wxar(data, dstdir, perm)
                arch += 1
                continue

            dst = dstdir / nam2
            # unlink an existing dst first so a reinstall can replace a file that
            # is currently executing (a wpexc/xwp still running from a prior
            # session) without ETXTBSY; copyfile/wpdecom then write a fresh file.
            try:
                if dst.exists():
                    dst.unlink()
            except OSError:
                pass
            # .drs/.lrs and standalone Type1 fonts are read by WP in native
            # form - ship verbatim, never decompress.
            if nam2.endswith((".drs", ".lrs", ".pfb", ".afm")):
                shutil.copyfile(src, dst); cp += 1
            else:
                r = self._run([str(self.wpdecom), str(src), str(dst)])
                if r.returncode == 2:                 # not compressed -> copy
                    shutil.copyfile(src, dst); cp += 1
                elif r.returncode != 0 or not dst.exists():
                    miss += 1; continue
                else:
                    dec += 1
            try:
                os.chmod(dst, int(perm, 8))
            except Exception:
                pass
        shlib = self.target / "shlib10"; shlib.mkdir(parents=True, exist_ok=True)
        supp = self._install_supplementary_fonts(shlib)
        nfonts = len(list(shlib.glob("*.pfb")))
        ndrv = len(list(shlib.glob("wp60*.all")))
        self.stats.update(decompressed=dec, copied=cp, missing=miss,
                          archives=arch, extracted=extracted,
                          supp_fonts=supp, fonts=nfonts, drivers=ndrv)
        return [f"decompressed {dec}, copied {cp}, missing {miss}",
                f"archives extracted: {arch}  ({extracted} members)",
                f"supplementary WP fonts from fonts/: {supp}",
                f"printer drivers: {ndrv}   Type1 fonts (.pfb): {nfonts}"]

    # ---- step 3: retarget libc5 ELF32 -----------------------------------
    def retarget(self):
        n = 0
        for f in self.target.rglob("*"):
            if not f.is_file() or not self._is_elf32(f):
                continue
            d = f.read_bytes()
            if b"libc.so.5\x00" not in d:
                continue
            d = d.replace(b"/lib/ld-linux.so.1\x00", b"/lib/ld-linux.so.2\x00")
            d = d.replace(b"libc.so.5\x00", b"retro5.so\x00")
            d = d.replace(b"libm.so.5\x00", b"libm.so.6\x00")
            f.write_bytes(d)
            self._hide_errno(f)
            n += 1
        self.stats["retargeted"] = n
        return [f"retargeted {n} libc5 binaries"]

    def _hide_errno(self, f: Path):
        """Mark the DEFINED dynsym 'errno' STV_HIDDEN (same as hidesym.py) so the
        non-TLS errno can't hijack glibc's TLS errno. _errno stays exported."""
        d = bytearray(f.read_bytes())
        if d[:4] != b"\x7fELF" or d[4] != 1:
            return
        e_shoff = struct.unpack_from("<I", d, 0x20)[0]
        e_shentsz = struct.unpack_from("<H", d, 0x2e)[0]
        e_shnum = struct.unpack_from("<H", d, 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x32)[0]
        def shdr(i):
            o = e_shoff + i * e_shentsz
            return struct.unpack_from("<IIIIIIIIII", d, o)
        _, _, _, _, so_off, _, _, _, _, _ = shdr(e_shstrndx)
        def secname(n):
            o = so_off + n
            return d[o:d.index(0, o)].decode(errors="replace")
        dynsym = dynstr = None
        for i in range(e_shnum):
            nm = shdr(i)
            name = secname(nm[0])
            if name == ".dynsym": dynsym = nm
            elif name == ".dynstr": dynstr = nm
        if not dynsym or not dynstr:
            return
        sym_off, sym_size = dynsym[4], dynsym[5]
        str_off = dynstr[4]
        for i in range(sym_size // 16):
            o = sym_off + i * 16
            st_name = struct.unpack_from("<I", d, o)[0]
            st_shndx = struct.unpack_from("<H", d, o + 14)[0]
            no = str_off + st_name
            name = d[no:d.index(0, no)].decode(errors="replace")
            if name == "errno" and st_shndx != 0:
                d[o + 13] = (d[o + 13] & ~0x3) | 2      # STV_HIDDEN
        f.write_bytes(d)

    # ---- step 4: guarded binary patches ---------------------------------
    def patches(self):
        out = []
        xwp = self.target / "wpbin/xwp"
        if not xwp.is_file():
            return ["xwp not found - skipped morph patch"]
        b = bytearray(xwp.read_bytes())
        applied = already = 0
        for off, exp, new in MORPH_PATCHES:
            if off + len(exp) > len(b):
                continue
            cur = bytes(b[off:off + len(exp)])
            if cur == new:
                already += 1
            elif cur == exp:
                b[off:off + len(new)] = new
                applied += 1
                out.append(f"morph patch: APPLIED at 0x{off:x} "
                           f"(NOP dead OOB strcpy in mor_read_entry)")
        if applied:
            xwp.write_bytes(b)
        elif already:
            out.append("morph patch: already applied")
        else:
            out.append("morph patch: no known buggy signature matched "
                       "(safe: xwp left untouched)")
        return out

    def _is_system_install(self) -> bool:
        """True when installing outside the user's home (e.g. /opt) - the tree
        is root-owned and must be world-readable so every user can run WP."""
        try:
            self.target.resolve().relative_to(Path.home().resolve()); return False
        except ValueError:
            return True

    # ---- step 5: permissions --------------------------------------------
    def fix_perms(self):
        # WP probes its config files (.prs/.set/.admin/...) with access(R_OK|W_OK)
        # and can trip on unreadable files. Ensure owner rw everywhere; for a
        # SYSTEM install also make everything world-readable (dirs traversable)
        # so non-root users can read the shared tree. Never strips exec bits.
        sysinstall = self._is_system_install()
        add = 0o644 if sysinstall else 0o600           # o+r/g+r only for system
        n = 0
        for f in self.target.rglob("*"):
            if f.is_symlink():
                continue
            m = stat.S_IMODE(f.stat().st_mode)
            if f.is_dir():
                want = m | (0o755 if sysinstall else 0o700)
            else:
                want = m | add
            if want != m:
                os.chmod(f, want); n += 1
        self.stats["perms_fixed"] = n
        scope = "world-readable" if sysinstall else "owner rw"
        return [f"ensured {scope} on {n} paths (fixes WP R_OK|W_OK probes)"]

    # ---- step 6: runtime config -----------------------------------------
    @staticmethod
    def _empty_wpc_record_file() -> bytes:
        """A valid, EMPTY WPC record file (magic + header + 0-record index),
        padded so WP's block reads never short. See wpcrec/."""
        HDR = 0x200
        buf = bytearray(HDR * 2)                 # 0x400, padded
        buf[0:4] = b"\xffWPC"
        struct.pack_into("<I", buf, 0x04, len(buf))    # doc_ptr / size
        buf[0x08] = 1; buf[0x09] = 1                    # product/file type
        struct.pack_into("<H", buf, 0x0e, HDR)         # index_ptr (>0x17)
        struct.pack_into("<I", buf, 0x10, 4)
        struct.pack_into("<I", buf, 0x14, len(buf))
        ih = HDR
        buf[ih] = 0x02; struct.pack_into("<H", buf, ih + 2, 1); buf[ih + 15] = 0x01
        return bytes(buf)

    # trusted 32-bit multiarch dir ld.so searches by default (no LD_LIBRARY_PATH)
    SYSTEM_SHIM_DIR = Path("/usr/lib/i386-linux-gnu")

    def install_shim(self):
        """Place retro5.so where the dynamic loader finds it.

        System install: into /usr/lib/i386-linux-gnu (a default search dir) and
        run ldconfig — one copy serves every versioned tree, and no launcher
        LD_LIBRARY_PATH is needed. User install (no root): into <target>/shbin10,
        and the launcher adds just that one dir to LD_LIBRARY_PATH.
        """
        out = []
        if self._is_system_install():
            self.SYSTEM_SHIM_DIR.mkdir(parents=True, exist_ok=True)
            dst = self.SYSTEM_SHIM_DIR / "retro5.so"
            shutil.copyfile(self.retro5, dst); os.chmod(dst, 0o644)
            self._run(["ldconfig"])
            self._shim_ldpath = None                # loader finds it by default
            out.append(f"installed retro5.so -> {dst} + ldconfig (no LD_LIBRARY_PATH)")
        else:
            shbin = self.target / "shbin10"; shbin.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.retro5, shbin / "retro5.so")
            self._shim_ldpath = '$ROOT/shbin10'     # one dir, not the old hack
            out.append("installed retro5.so into shbin10")
        return out

    def _run_wpfi(self) -> bool:
        """Generate wp.drs (+ fonts) by running WordPerfect's own file/font
        installer, exactly as the Corel Linux .deb postinst does:
        `( cd shbin10; ./wpfi )`. wp.drs is referenced by xwp/wpfi/xwppmgr at
        runtime but is shipped in NO edition — it is *generated* by wpfi. Our
        tree-copy install never runs the .deb's maintainer scripts, so wpfi never
        ran and wp.drs was never created (WP then errors at startup). wpfi is
        retargeted with the rest of the tree and runs HEADLESS under the shim
        (no X libs). Must run AFTER install_shim so the loader finds retro5.so.
        Returns True if wp.drs exists afterward."""
        shbin = self.target / "shbin10"
        wpfi  = shbin / "wpfi"
        drs   = self.target / "shlib10" / "wp.drs"
        if not (wpfi.exists() and os.access(wpfi, os.X_OK)):
            return drs.exists()                 # native discs ship wp.drs directly
        env = dict(os.environ)
        env["WPC"] = str(self.target)
        env.setdefault("XLOCALEDIR", "/usr/share/X11/locale")
        if getattr(self, "_shim_ldpath", None): # user install: shim lives in shbin10
            prev = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = str(shbin) + (":" + prev if prev else "")
        try:
            self._run(["./wpfi"], cwd=str(shbin), env=env)
        except Exception:                        # noqa - never let wpfi abort the install
            pass
        # wpfi initializes WP's print-exchange mailbox /tmp/wpc-$USER-$HOST. In a
        # system/root install it inherits USER=<invoker> from the environment but
        # creates that dir ROOT-owned (0755). A later normal-user launch then can't
        # create its .wpexc8.LCK inside it (EACCES) -> WP's fork of the wpexc helper
        # exits 1 -> the misleading "Cannot create a new process" dialog. Remove any
        # root-owned mailbox so the user's first run makes a fresh, user-owned one.
        # Only touch root-owned dirs — a real user's live mailbox is user-owned, so
        # this never disturbs a running session, and it also self-heals a VM already
        # broken by an earlier root run.
        if os.geteuid() == 0:
            for d in Path("/tmp").glob("wpc-*"):
                try:
                    if d.is_dir() and d.stat().st_uid == 0:
                        shutil.rmtree(d, ignore_errors=True)
                except OSError:
                    pass
        return drs.exists()

    def runtime_config(self):
        out = self.install_shim()
        shlib = self.target / "shlib10"; shlib.mkdir(parents=True, exist_ok=True)
        cfgmode = 0o644 if self._is_system_install() else 0o600
        # VALID empty .wpc.admin (build-tree.sh wrote a 0-byte one -> File IO Error).
        admin = shlib / ".wpc.admin"
        admin.write_bytes(self._empty_wpc_record_file()); os.chmod(admin, cfgmode)
        out.append("wrote valid empty .wpc.admin")
        # .wp8.lm: xwp's license check (FUN_0850c9d0) returns "licensed" the moment
        # access(shlib10/.wp8.lm, R_OK)==0, skipping the FLEXlm checkout and the
        # "evaluation period" nag. WP creates it after one accepted run; we create
        # it up front so a fresh install never nags. MUST be readable by the user.
        lm = shlib / ".wp8.lm"
        lm.write_bytes(b""); os.chmod(lm, 0o644)
        out.append("wrote .wp8.lm (suppresses the FLEXlm evaluation nag)")
        wplib = self.target / "wplib"; wplib.mkdir(parents=True, exist_ok=True)
        for m in (".def.lang", ".license"):
            p = wplib / m
            if not p.exists():
                p.write_bytes(b"")
        # ship the installer scripts into the tree so the uninstall menu entry
        # (and later repairs) work even if the original checkout is gone
        srcdir = Path(__file__).resolve().parent
        insdir = self.target / "installer"; insdir.mkdir(parents=True, exist_ok=True)
        copied = 0
        for name in ("wp8_install.py", "wp8_installer.py"):
            s = srcdir / name
            if s.is_file():
                shutil.copyfile(s, insdir / name); os.chmod(insdir / name, 0o755); copied += 1
        if copied:
            out.append(f"embedded installer/uninstaller ({copied} scripts) in {insdir}")
        out += self._ensure_runtime_resources()
        return out

    def _ensure_runtime_resources(self):
        """Fill in runtime resource files some editions/packagings omit, so WP
        doesn't die on a missing file at startup."""
        out = []
        shlib = self.target / "shlib10"
        # (1) passpost.prs: WP's factory "Passthru PostScript" printer resource.
        # WP's default-printer record (key 0x01 in .wpc8x.set/.wpc.admin) selects
        # this printer BY NAME, so WP then loads shlib10/passpost.prs and errors
        # "File not found ... passpost.prs" if it's absent. It is a SPECIFIC
        # printer definition (~24 KB) — NOT interchangeable with default.prs
        # (~86 KB, a different, generic printer): fabricating passpost.prs from
        # default.prs yields a wrong/broken default printer. Native discs ship the
        # genuine file (install_tree copies it from the ship manifest); some
        # packagings (the Corel Linux .deb) omit it. Recover it the same way we do
        # wp.drs — COPY the genuine file from a sibling WP install — never
        # fabricate one. We can't redistribute Corel's .prs ourselves.
        pp = shlib / "passpost.prs"
        if not pp.exists():
            found = None
            base = self.target.parent
            if base.is_dir():
                for sib in sorted(base.iterdir()):
                    cand = sib / "shlib10/passpost.prs"
                    if not (cand.is_file() and cand.resolve() != pp.resolve()):
                        continue
                    # Skip a sibling's FABRICATED passpost (a byte-copy of its own
                    # default.prs, from the old self-heal) — only ever propagate a
                    # genuine printer resource, never re-spread the wrong one.
                    dflt = sib / "shlib10/default.prs"
                    if dflt.is_file() and filecmp.cmp(cand, dflt, shallow=False):
                        continue
                    found = cand; break
            if found:
                shutil.copyfile(found, pp); os.chmod(pp, 0o644)
                out.append(f"passpost.prs was missing (this packaging omits it) — "
                           f"copied the genuine one from {found}")
            else:
                # passpost.prs isn't shipped by ANY edition — WP generates it at
                # runtime, and the ship manifest carries only default.prs +
                # pssave.prs. For a single fresh install (no sibling to copy from),
                # seed it from the shipped, GENUINE pssave.prs: a real PostScript
                # printer, structurally ~= passpost (NOT the generic default.prs).
                ps = shlib / "pssave.prs"
                if ps.is_file():
                    shutil.copyfile(ps, pp); os.chmod(pp, 0o644)
                    out.append("passpost.prs was missing — seeded it from the shipped "
                               "pssave.prs (a genuine PostScript printer). It prints "
                               "PostScript; point the printer's destination at your "
                               "lpr/CUPS command to print to hardware.")
                else:
                    out.append("WARNING: passpost.prs and pssave.prs are both missing "
                               "— WP's default printer won't open. (Not fabricating "
                               "from default.prs, a different generic printer.)")
        # (2) wp.drs: the display-resource file. It is referenced by
        # xwp/wpfi/xwppmgr at runtime but shipped by NO edition — WP *generates*
        # it via wpfi (its file/font installer). The Corel Linux .deb creates it
        # in its postinst (`cd shbin10; ./wpfi`), which our tree-copy install
        # never runs, so wp.drs is missing and WP errors at startup. Fix, in
        # order: (a) generate it properly with wpfi (works for a lone install),
        # (b) borrow a compatible one from a sibling WP install, (c) warn.
        drs = shlib / "wp.drs"
        if not drs.exists():
            if self._run_wpfi() and drs.exists():
                try: os.chmod(drs, 0o644)
                except OSError: pass
                out.append("generated wp.drs via wpfi (WP's file/font installer, "
                           "as the Corel .deb postinst does)")
            else:
                found = None
                base = self.target.parent
                if base.is_dir():
                    for sib in sorted(base.iterdir()):
                        cand = sib / "shlib10/wp.drs"
                        if cand.is_file() and cand.resolve() != drs.resolve():
                            found = cand; break
                if found:
                    shutil.copyfile(found, drs); os.chmod(drs, 0o644)
                    out.append(f"wp.drs was missing; wpfi didn't produce one — "
                               f"copied a compatible one from {found}")
                else:
                    out.append("WARNING: wp.drs is missing, wpfi didn't generate it, "
                               "and no sibling WordPerfect install has one to copy. "
                               "WP will error at startup. Install a native WP disc "
                               "alongside (its wp.drs will be reused).")
        # (3) XKeysymDB: WP's bundled 1998 libX11 resolves Motif virtual keysyms
        # (osfDelete/osfLeft/...) used by dialog text-field translations through
        # this file. Modern X dropped it, so without it Delete/BackSpace/arrow
        # keys self-insert garbage in entry fields. Ship our copy; the launcher
        # points XKEYSYMDB at it. (Standard MIT-licensed X11 keysym data.)
        xkdb = shlib / "XKeysymDB"
        if not xkdb.exists():
            src = Path(__file__).resolve().parent / "XKeysymDB"
            if src.is_file():
                shutil.copyfile(src, xkdb); os.chmod(xkdb, 0o644)
                out.append("installed shlib10/XKeysymDB (OSF virtual keysyms so "
                           "Delete/arrows work in dialog text fields)")
        return out

    # ---- step 7: launcher -----------------------------------------------
    LAUNCHER = """#!/bin/bash
# xwp - WordPerfect 8 launcher (generated by wp8 installer).
ROOT="{root}"
# Per-user first-run seed: WP needs ~/.wprc/.wpc8x.set or it errors at startup.
# Done here so a system-wide (/opt) install works for every user automatically.
if [ ! -e "$HOME/.wprc/.wpc8x.set" ] && [ -f "$ROOT/shlib10/.wpc8x.set" ]; then
    mkdir -p "$HOME/.wprc"
    cp "$ROOT/shlib10/.wpc8x.set" "$HOME/.wprc/.wpc8x.set" 2>/dev/null
    chmod 0600 "$HOME/.wprc/.wpc8x.set" 2>/dev/null
fi
# self-heal WP's default printer resource: WP's default-printer record selects
# "Passthru PostScript" by name, so it loads shlib10/passpost.prs and errors
# "File not found ... passpost.prs" if it's absent. passpost.prs is a SPECIFIC
# printer, NOT default.prs (a different, generic printer) — so copy the genuine
# file from a sibling install if this tree lacks it; never fabricate it.
if [ ! -e "$ROOT/shlib10/passpost.prs" ]; then
    for _sib in "$ROOT"/../*/shlib10/passpost.prs; do
        [ -f "$_sib" ] || continue
        # skip a sibling's fabricated passpost (a copy of its own default.prs)
        cmp -s "$_sib" "${{_sib%passpost.prs}}default.prs" && continue
        cp "$_sib" "$ROOT/shlib10/passpost.prs" 2>/dev/null; break
    done
    # no genuine sibling: seed from the shipped pssave.prs (a real PostScript
    # printer), never from default.prs (a different, generic printer).
    [ ! -e "$ROOT/shlib10/passpost.prs" ] && [ -f "$ROOT/shlib10/pssave.prs" ] && \
        cp "$ROOT/shlib10/pssave.prs" "$ROOT/shlib10/passpost.prs" 2>/dev/null
fi
xhost +local: >/dev/null 2>&1
# WP's Motif menus ask the X server for -adobe-helvetica-*-75-75-iso8859-1;
# without those bitmap fonts on the server's FONT PATH the menus fall back to an
# ugly `fixed` font. Installing the xfonts-* packages adds the dirs, but a
# server that was already running won't have them in its path — add them here at
# launch (and rehash) so the nice font shows without a logout. Harmless if xset
# or the dirs are absent.
if command -v xset >/dev/null 2>&1; then
    for _fp in /usr/share/fonts/X11/75dpi /usr/share/fonts/X11/100dpi \
               /usr/share/fonts/X11/Type1 /usr/share/fonts/X11/misc; do
        [ -d "$_fp" ] && xset +fp "$_fp" 2>/dev/null
    done
    xset fp rehash 2>/dev/null
fi
{ldlib}export WPC="$ROOT"
# point the ancient statically-linked Xlib at the modern X locale dir
export XLOCALEDIR=/usr/share/X11/locale
# supply the OSF virtual keysyms WP's 1998 libX11 needs (modern X dropped the
# XKeysymDB file); without it Delete/BackSpace/arrow keys self-insert garbage
# in dialog text fields (e.g. the Save As filename box)
[ -f "$ROOT/shlib10/XKeysymDB" ] && export XKEYSYMDB="$ROOT/shlib10/XKeysymDB"
export WPIPEDELAY=60
: "${{DISPLAY:=:0}}"; export DISPLAY
# NB: do NOT set WPLANG (sends xwp down a broken admintxt path)
# Bigger menus: WP's default Motif font is a tiny 8pt helvetica (unreadable on
# modern high-res displays). -fontSize scales the whole UI; default to a
# readable 17, override with $WPFONTSIZE (or pass your own -fontSize after).
exec "$ROOT/wpbin/xwp" -fontSize "${{WPFONTSIZE:-17}}" "$@"
"""

    def launcher(self):
        if not self.make_launcher:
            self.launcher_path = None
            return ["launcher: skipped"]
        out = []
        # System install -> system-wide launcher/menu (we're root here); the
        # launcher self-seeds each user's ~/.wprc at first run. User install ->
        # per-user under ~/.local.
        if self._is_system_install():
            bindir = Path("/usr/local/bin"); appdir = Path("/usr/share/applications")
        else:
            bindir = Path.home() / ".local/bin"; appdir = Path.home() / ".local/share/applications"
        bindir.mkdir(parents=True, exist_ok=True)
        # version-suffixed launcher so 8.0 and 8.1 install side by side
        vsuffix = "" if self.version in ("", "8") else f"-{self.version}"
        ldlib = "" if not getattr(self, "_shim_ldpath", None) \
                else f'export LD_LIBRARY_PATH="{self._shim_ldpath}"\n'
        lp = bindir / f"xwp{vsuffix}"
        lp.write_text(self.LAUNCHER.format(root=self.target, ldlib=ldlib))
        os.chmod(lp, 0o755)
        self.launcher_path = lp
        out.append(f"launcher: {lp}")
        if self.make_desktop:
            appdir.mkdir(parents=True, exist_ok=True)
            # install the real WP icon and point the entry at it (absolute path;
            # gdk-pixbuf/GNOME render XPM fine). Fall back to a themed name.
            icon = "x-office-document"
            # native disc: linux/link/wp.xpm; .deb suite: usr/X11R6/share/icons/*.xpm
            src_icon = self._find_icon()
            if src_icon:
                icondir = self.target / "icon"; icondir.mkdir(parents=True, exist_ok=True)
                dxpm = icondir / "wp.xpm"
                shutil.copyfile(src_icon, dxpm); os.chmod(dxpm, 0o644)
                icon = str(dxpm)
                out.append(f"installed icon: {dxpm}")
            name = f"WordPerfect {self.version}" if self.version not in ("", "8") else "WordPerfect 8"
            dp = appdir / f"wordperfect{self.version}.desktop"
            # StartupWMClass lets GNOME/Mutter bind xwp's window (static Xlib sets a
            # classic WM_CLASS) to this entry, so it shows this icon and doesn't
            # spawn a duplicate dash icon.
            dp.write_text(
                f"[Desktop Entry]\nType=Application\nName={name}\n"
                f"Exec={lp} %f\nTerminal=false\nCategories=Office;WordProcessor;\n"
                f"Icon={icon}\nKeywords=WordPerfect;WP;word;\n"
                "StartupNotify=false\nStartupWMClass=XWp\n"
                "Actions=NewDocument;\n"
                "\n[Desktop Action NewDocument]\n"
                "Name=New Document\n"
                f"Exec={lp}\n"
                f"Icon={icon}\n")
            os.chmod(dp, 0o644)
            out.append(f"desktop entry: {dp} (+ New Document action)")
            # matching uninstall entry -> launches the embedded wizard in uninstall mode
            insui = self.target / "installer" / "wp8_installer.py"
            up = appdir / f"wordperfect{self.version}-uninstall.desktop"
            up.write_text(
                f"[Desktop Entry]\nType=Application\nName=Uninstall {name}\n"
                f"Exec=python3 {insui} --uninstall\nTerminal=false\n"
                "Icon=edit-delete\nCategories=System;\nNoDisplay=false\n")
            os.chmod(up, 0o644)
            out.append(f"uninstall entry: {up}")
        else:
            out.append("desktop entry: skipped")
        if str(bindir) not in os.environ.get("PATH", ""):
            out.append(f"note: add {bindir} to PATH, or run {lp} directly")
        return out

    # ---- pre-bake the print Destination so a fresh install prints ---------
    def _prebake_lp_destination(self, setfile) -> bool:
        """Set the "Passthru PostScript" printer's Destination to `lp  <f>` (pipe
        PostScript to the CUPS default printer; `<f>` = spool file) in a
        .wpc8x.set. WP defaults the Destination to *None* -> "Invalid printer
        destination", so out of the box nothing prints until the user sets it by
        hand. The Destination lives in the key-0x01 printer record of .wpc8x.set
        (NOT in passpost.prs), as an ASCII sub-record: a port name at +0x11 and
        the command at +0x3a of a block at file offset 0x408. Byte layout RE'd
        from a working install. Guarded: only the "Passthru PostScript" record,
        and only when the Destination is currently empty (never clobbers a
        user-set one). Idempotent. Returns True if a destination is now present.

        NOTE: some packagings (the .deb) have WP *generate* .wpc8x.set at first
        run, so there's nothing to patch at install time — those still need the
        one-time manual Destination step (documented). Best-effort."""
        try:
            data = bytearray(Path(setfile).read_bytes())
        except OSError:
            return False
        OFF = 0x408
        if data[:4] != b"\xffWPC" or len(data) < OFF + 66:
            return False
        # guard: key-0x01 record must be the Passthru PostScript printer
        name = data[0x21e:0x21e + 38].decode("utf-16le", "replace").split("\x00")[0]
        if name != "Passthru PostScript":
            return False
        # already has a destination? leave it untouched (idempotent, no clobber)
        if b"<f>" in bytes(data[OFF:OFF + 66]) or data[OFF + 0x11:OFF + 0x18].strip(b"\x00"):
            return True
        DEST = bytearray(66)
        DEST[0:17] = b"\x58\x02\x00\x00\x86\x00\x0a\x00\x00\x00\x00\x00\x07\x02\x00\x00\x00"
        DEST[17:24] = b"WPSpool"           # +0x11: the print port name
        DEST[58:66] = b"lp  <f>\x00"        # +0x3a: the command (pipe PS to CUPS)
        data[OFF:OFF + 66] = DEST
        Path(setfile).write_bytes(bytes(data))
        return b"lp  <f>" in Path(setfile).read_bytes()

    # ---- step 8: per-user setup -----------------------------------------
    def user_setup(self):
        if self._is_system_install():
            # can't seed every user's home from here; the launcher self-seeds
            # ~/.wprc/.wpc8x.set on each user's first run instead.
            return ["per-user setup: deferred to first run (launcher self-seeds ~/.wprc)"]
        out = []
        wprc = Path.home() / ".wprc"; wprc.mkdir(parents=True, exist_ok=True)
        # WP searches ~/.wprc for .wpc8x.set at startup; missing -> File IO Error.
        dst = wprc / ".wpc8x.set"
        if not dst.exists():
            tmpl = self.target / "shlib10/.wpc8x.set"
            if tmpl.is_file():
                shutil.copyfile(tmpl, dst)
                out.append("seeded ~/.wprc/.wpc8x.set from template")
            else:
                dst.write_bytes(self._empty_wpc_record_file())
                out.append("seeded ~/.wprc/.wpc8x.set (generated empty)")
            os.chmod(dst, 0o600)
        else:
            out.append("~/.wprc/.wpc8x.set already present")
        # pre-set the print Destination to `lp` so printing works out of the box
        # (WP defaults it to None -> "Invalid printer destination"). Patch both the
        # shlib10 seed (for future users) and this user's copy. No-op if absent /
        # already set / not the Passthru PostScript record.
        for s in (self.target / "shlib10/.wpc8x.set", dst):
            if s.is_file() and self._prebake_lp_destination(s):
                out.append(f"pre-set print Destination = 'lp' in {s.name} ({s.parent.name})")
                break
        return out

    # ---- complete: repair an existing root (no binary reinstall) ---------
    def complete(self, root):
        """Install just the pieces a plain tree-build misses — the wxar font/
        data archives, the printer drivers, a valid .wpc.admin — and fix perms,
        on an EXISTING install root, WITHOUT re-installing or un-retargeting
        binaries. Single source of truth for finish-wp-install.sh. Needs media."""
        root = Path(root)
        shlib = root / "shlib10"
        if not shlib.is_dir():
            raise InstallError(f"no shlib10 under {root}")
        self.prereqs()                      # media present + wpdecom2 built
        arch = extracted = ndrv = 0
        for src, dir2, nam2, perm, opt in self._ship_entries():
            if not src.is_file():
                continue
            typ = opt[-1] if len(opt) == 3 else "c"
            if typ == "a" and dir2.split("/")[0] == "shlib10":       # font/data archives
                dstdir = root / dir2; dstdir.mkdir(parents=True, exist_ok=True)
                data = self._archive_bytes(src)
                if data is not None:
                    extracted += self.extract_wxar(data, dstdir, perm); arch += 1
            elif (dir2 == "shlib10" and nam2.lower().startswith("wp60")
                  and nam2.lower().endswith(".all")):                # printer drivers
                data = self._archive_bytes(src)
                if data is not None:
                    (shlib / nam2).write_bytes(data)
                    os.chmod(shlib / nam2, 0o644); ndrv += 1
            elif dir2 == "shlib10" and nam2.lower().endswith((".pfb", ".afm")):
                shutil.copyfile(src, shlib / nam2)      # standalone font (wpco03n_)
                os.chmod(shlib / nam2, 0o644)
        supp = self._install_supplementary_fonts(shlib)
        (shlib / ".wpc.admin").write_bytes(self._empty_wpc_record_file())
        os.chmod(shlib / ".wpc.admin", 0o600)
        (shlib / ".wp8.lm").write_bytes(b""); os.chmod(shlib / ".wp8.lm", 0o644)  # kill eval nag
        self.target = root
        permlog = self.fix_perms()
        return [f"font archives: {arch} ({extracted} members) + {supp} supplementary",
                f"printer drivers: {ndrv}",
                "valid .wpc.admin written"] + permlog

    # ---- uninstall -------------------------------------------------------
    def uninstall(self, root, remove_profile=False):
        """Remove an install: the tree, its launcher, and its menu entry (from
        the system or user locations, matching how it was installed). Leaves the
        user's ~/.wprc profile + documents unless remove_profile=True. For a
        /opt install this must run as root (the GUI elevates with pkexec)."""
        root = Path(root)
        self.target = root
        system = self._is_system_install()
        out = []
        if root.exists():
            # safety: only nuke something that actually looks like a WP8 install
            if not ((root / "wpbin" / "xwp").exists() or (root / "shlib10").is_dir()):
                raise InstallError(f"{root} does not look like a WP8 install "
                                   "(no wpbin/xwp or shlib10) - refusing to delete")
            try:
                shutil.rmtree(root); out.append(f"removed install tree: {root}")
            except OSError as e:
                out.append(f"could not remove {root} ({e.strerror}) - rerun as root")
        else:
            out.append(f"tree already gone: {root}")
        if system:
            lp = Path("/usr/local/bin/xwp"); dp = Path("/usr/share/applications/wordperfect8.desktop")
        else:
            lp = Path.home() / ".local/bin/xwp"; dp = Path.home() / ".local/share/applications/wordperfect8.desktop"
        # only touch a launcher/menu entry that actually points at THIS root
        mine = lp.exists() and f'ROOT="{root}"' in lp.read_text(errors="replace")
        if mine:
            try:
                lp.unlink(); out.append(f"removed launcher: {lp}")
            except OSError as e:
                out.append(f"could not remove {lp} ({e.strerror}) - rerun as root")
            for entry in (dp, dp.with_name("wordperfect8-uninstall.desktop")):
                if entry.exists():
                    try:
                        entry.unlink(); out.append(f"removed menu entry: {entry}")
                    except OSError as e:
                        out.append(f"could not remove {entry} ({e.strerror}) - rerun as root")
        elif lp.exists():
            out.append(f"left {lp} (points at a different install)")
        if remove_profile:
            prof = Path.home() / ".wprc"
            if prof.exists():
                shutil.rmtree(prof, ignore_errors=True); out.append(f"removed profile: {prof}")
        else:
            out.append("kept your ~/.wprc profile and documents")
        return out

    def _find_icon(self):
        """Locate a WordPerfect .xpm icon in the source media (native or .deb)."""
        native = self.media / "linux/link/wp.xpm"
        if native.is_file():
            return native
        # .deb suite ships icons under usr/X11R6/share/icons — search up from the
        # wp tree (media is .../usr/lib/wp8; icons are .../usr/X11R6/...).
        p = self.media
        for _ in range(5):
            icodir = p / "usr/X11R6/share/icons"
            if icodir.is_dir():
                wp = [x for x in icodir.glob("*.xpm") if "wp" in x.name.lower()]
                if wp:
                    return wp[0]
                anyx = sorted(icodir.glob("*.xpm"))
                if anyx:
                    return anyx[0]
            p = p.parent
        return None

    # ---- .deb (suite) install path --------------------------------------
    def prereqs_deb(self) -> list[str]:
        log = []
        log += self._guard_target()          # bail before touching anything
        if self.install_deps:
            log += self._install_deps()
        if not (self.media / "wpbin/xwp").is_file():
            raise InstallError(f"no WordPerfect tree (wpbin/xwp) at {self.media}")
        if not Path("/lib/ld-linux.so.2").exists():
            raise InstallError("32-bit loader /lib/ld-linux.so.2 missing "
                               "(install libc6:i386)")
        if not self.retro5.exists():                 # build the shim if needed
            alt = self.compat / "build/retro5.so"
            if alt.exists():
                self.retro5 = alt
            elif (self.compat / "Makefile").exists():
                r = self._run(["make", "-C", str(self.compat)])
                if r.returncode != 0 or not self.retro5.exists():
                    raise InstallError("failed to build retro5.so:\n" + r.stderr)
                log.append("built retro5.so")
            else:
                raise InstallError("retro5.so not found and cannot build it")
        log.append(f"shim: {self.retro5}")
        return log

    @staticmethod
    def _replace_copy(src, dst, *, follow_symlinks=True):
        """copy2 that UNLINKS an existing dst first, so replacing a file that is
        currently *executing* — a wpexc/xwp still running from a prior session —
        works instead of failing with ETXTBSY ("Text file busy"). The running
        process keeps the old inode; we write a fresh file. (This is how package
        managers replace live binaries.) Used on --overwrite reinstalls."""
        try:
            if os.path.lexists(dst):
                os.unlink(dst)
        except OSError:
            pass
        shutil.copy2(src, dst, follow_symlinks=follow_symlinks)
        return dst

    def install_tree_deb(self) -> list[str]:
        # a .deb already holds an installed, uncompressed tree (binaries, .drs in
        # runtime form, fonts) — just copy it into the versioned target. Use
        # unlink-first copies so a reinstall over a tree with a live wpexc/xwp
        # doesn't fail with "Text file busy".
        self.target.mkdir(parents=True, exist_ok=True)
        n = 0
        for item in sorted(self.media.iterdir()):
            dst = self.target / item.name
            if item.is_dir():
                shutil.copytree(item, dst, dirs_exist_ok=True,
                                copy_function=self._replace_copy)
            else:
                self._replace_copy(item, dst)
            n += 1
        # drop the bundled ancient libc5/libm5 — the retarget points every binary
        # at retro5.so + glibc, so these would only be a foot-gun if ever found.
        for pat in ("libc.so.5*", "libm.so.5*"):
            for f in (self.target / "wpbin").glob(pat):
                f.unlink()
        # Gather WP's shlib10 runtime resources (graphic fonts, printer drivers,
        # .prs) from anywhere in the media — the .deb keeps only Courier-WP in
        # the tree and stashes the other fonts under the X11 Type1 dir, so a bare
        # tree-copy otherwise leaves the document font list showing only
        # Courier-WP.
        shlib = self.target / "shlib10"
        nres = self._harvest_shlib_resources(shlib)
        out = [f"copied WordPerfect {self.version} suite tree "
               f"({n} entries) to {self.target}"]
        if nres:
            out.append(f"gathered {nres} font/driver resource file(s) into shlib10")
        # wp.drs is WP's FONT REGISTRY — WP lists a graphic font only if wp.drs
        # names it, regardless of which .pfb files exist. The .deb ships no
        # wp.drs, so any present here is one WE generated on a PRIOR install —
        # possibly before the fonts above were gathered, i.e. registering only
        # Courier-WP. Since _ensure_runtime_resources regenerates wp.drs (via
        # wpfi) only when it is ABSENT, a reinstall would otherwise keep that
        # stale registry and the new faces would never show. Drop it so wpfi
        # rebuilds it against the now-complete font set.
        drs = shlib / "wp.drs"
        if drs.exists():
            try:
                drs.unlink()
                out.append("removed stale wp.drs so it is rebuilt for the current "
                           "font set")
            except OSError:
                pass
        return out

    # ---- orchestration ---------------------------------------------------
    STEPS = [
        ("prereqs",        "Checking prerequisites",  0.05, "prereqs"),
        ("install_tree",   "Installing files",        0.55, "install_tree"),
        ("retarget",       "Retargeting binaries",    0.72, "retarget"),
        ("patches",        "Applying patches",        0.78, "patches"),
        ("fix_perms",      "Setting permissions",     0.85, "fix_perms"),
        ("runtime_config", "Installing runtime",      0.90, "runtime_config"),
        ("launcher",       "Creating launcher",       0.95, "launcher"),
        ("user_setup",     "Per-user setup",          1.00, "user_setup"),
    ]
    DEB_STEPS = [
        ("prereqs",        "Checking prerequisites",  0.05, "prereqs_deb"),
        ("install_tree",   "Installing suite files",  0.45, "install_tree_deb"),
        ("retarget",       "Retargeting binaries",    0.70, "retarget"),
        ("patches",        "Applying patches",        0.76, "patches"),
        ("fix_perms",      "Setting permissions",     0.84, "fix_perms"),
        ("runtime_config", "Installing runtime",      0.90, "runtime_config"),
        ("launcher",       "Creating launcher",       0.95, "launcher"),
        ("user_setup",     "Per-user setup",          1.00, "user_setup"),
    ]

    def run(self):
        steps = self.DEB_STEPS if self.source_kind == "deb" else self.STEPS
        if self.tree_only:
            steps = [s for s in steps if s[0] not in ("launcher", "user_setup")]
        for key, title, frac, meth in steps:
            try:
                log = getattr(self, meth)()
                yield Step(key, title, frac, ok=True, log=log or [])
            except InstallError as e:
                yield Step(key, title, frac, ok=False, detail=str(e))
                return
            except Exception as e:  # noqa
                yield Step(key, title, frac, ok=False, detail=f"{type(e).__name__}: {e}")
                return


# ---- CLI (also lets the GUI reuse the same engine) ----------------------
def _load_media():
    """Import the sibling media module regardless of how we're invoked."""
    try:
        from . import media as m           # package import
        return m
    except (ImportError, ValueError):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import media as m
        return m


def _run_install(eng, target):
    ok = True
    for s in eng.run():
        mark = "OK " if s.ok else "FAIL"
        print(f"[{mark}] {int(s.fraction*100):3d}%  {s.title}")
        for l in s.log:
            print(f"        - {l}")
        if not s.ok:
            print(f"        ! {s.detail}"); ok = False
    if ok:
        lp = getattr(eng, "launcher_path", None)
        if lp:
            print(f"\nDone. Launch with:  {lp}")
        else:
            print(f"\nDone. Installed to {target} (no launcher created).")
        print("Tip: add -fontSize 20 for bigger menus on HiDPI.")
        print("File locking works through the shim, so no need to disable it "
              "(only turn it off in Preferences > File Locking if ~ is on NFS "
              "and you hit spurious 'file in use' dialogs).")
    return 0 if ok else 1


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="WordPerfect 8 installer (modern glibc)")
    ap.add_argument("--media", metavar="PATH",
                    help="Corel media to install from: an ISO, an extracted "
                         "native tree, or a folder containing ISOs")
    ap.add_argument("--target", default=None,
                    help="install dir (default: ~/.local/share/wordperfect/<version> "
                         "so 8.0 and 8.1 sit side by side)")
    ap.add_argument("--list", action="store_true",
                    help="list installable WordPerfect media found under --media "
                         "and exit")
    ap.add_argument("--pick", type=int, metavar="N",
                    help="when several versions are found, install candidate N "
                         "(indices from --list)")
    ap.add_argument("--install-deps", action="store_true",
                    help="detect the package manager (apt/dnf/pacman/zypper) and "
                         "install the 32-bit runtime libraries WP needs before installing")
    ap.add_argument("--deps-only", action="store_true",
                    help="just install the runtime dependencies (32-bit libs, CUPS "
                         "client, X fonts) and exit; needs root (the GUI elevates this "
                         "for a user install)")
    ap.add_argument("--overwrite", action="store_true",
                    help="install even if --target already exists and is "
                         "non-empty (replaces name-colliding files in place, no "
                         "backup); without it the install refuses and stops")
    ap.add_argument("--system", action="store_true",
                    help="install system-wide under /opt (world-readable, system "
                         "launcher) for all users. Implied when run as root; a "
                         "non-root user is elevated with pkexec.")
    ap.add_argument("--no-launcher", action="store_true")
    ap.add_argument("--no-desktop", action="store_true",
                    help="do not add an application-menu entry")
    ap.add_argument("--tree-only", action="store_true",
                    help="install tree/retarget/patch/config but not the "
                         "launcher/menu/~/.wprc")
    ap.add_argument("--complete", metavar="ROOT",
                    help="repair an existing install ROOT (fonts/drivers/.wpc.admin"
                         "/perms only, no binary reinstall) and exit")
    ap.add_argument("--uninstall", metavar="ROOT",
                    help="remove install ROOT + its launcher/menu entry and exit "
                         "(keeps ~/.wprc unless --remove-profile)")
    ap.add_argument("--remove-profile", action="store_true",
                    help="with --uninstall, also delete ~/.wprc")
    a = ap.parse_args(argv)

    # --- deps-only: install the runtime packages and exit (no media needed) ---
    if a.deps_only:
        try:
            for line in Engine(Path("."), Path("."))._install_deps():
                print(f"  - {line}")
            return 0
        except InstallError as e:
            print(f"FAIL: {e}"); return 1

    # --- repair / uninstall operate on an installed ROOT, no media needed ---
    if a.complete:
        try:
            # media = --media if given (needed for the font/data archives), else
            # assume the root is itself a native media tree.
            eng = Engine(a.media or a.complete, a.complete)
            for line in eng.complete(a.complete):
                print(f"  - {line}")
            print(f"\nCompleted {a.complete}.")
            return 0
        except InstallError as e:
            print(f"FAIL: {e}"); return 1
    if a.uninstall:
        try:
            eng = Engine(a.uninstall, a.target or DEFAULT_TARGET)
            for line in eng.uninstall(a.uninstall, remove_profile=a.remove_profile):
                print(f"  - {line}")
            print(f"\nUninstalled {a.uninstall}.")
            return 0
        except InstallError as e:
            print(f"FAIL: {e}"); return 1

    # --- fresh install: discover + resolve media (ISO / dir / folder-of-ISOs) ---
    if not a.media:
        ap.error("--media is required (an ISO, a native tree, or a folder of ISOs)")

    # --- system install: root implies it; a non-root user is elevated ---------
    # `--system` (or running as root) installs globally under /opt. When a
    # non-root user asks for it, re-run the whole command under pkexec so it can
    # write /opt + the system dirs (paths made absolute, since pkexec resets env).
    if a.system and os.geteuid() != 0:
        if not shutil.which("pkexec"):
            ap.error("--system needs root; install pkexec, or re-run with sudo")
        raw = list(argv)
        for k, tok in enumerate(raw):                 # make --media/--target absolute
            if tok in ("--media", "--target") and k + 1 < len(raw):
                raw[k + 1] = str(Path(raw[k + 1]).expanduser().resolve())
            elif tok.startswith(("--media=", "--target=")):
                key, val = tok.split("=", 1)
                raw[k] = f"{key}={Path(val).expanduser().resolve()}"
        print("system install requested — elevating with pkexec…", flush=True)
        os.execvp("pkexec", ["pkexec", sys.executable,
                             os.path.abspath(__file__)] + raw)   # replaces us

    media = _load_media()
    cands = media.discover([Path(a.media)])
    installable = [c for c in cands if c.installable]

    if a.list or not installable:
        print("Media found:")
        for i, c in enumerate(cands):
            tag = "INSTALL" if c.installable else "skip"
            print(f"  [{i}] ({tag:7}) {c.label}")
        if not installable:
            print("\nNo installable WordPerfect-for-Linux media found here.")
            return 1
        if a.list:
            return 0

    if a.pick is not None:
        if not (0 <= a.pick < len(cands)) or not cands[a.pick].installable:
            ap.error(f"--pick {a.pick} is not an installable candidate (see --list)")
        chosen = cands[a.pick]
    elif len(installable) == 1:
        chosen = installable[0]
    else:
        print("Several installable versions found — choose one with --pick N:")
        for i, c in enumerate(cands):
            if c.installable:
                print(f"  --pick {i}   {c.label}")
        return 2

    try:
        with media.resolve(chosen.path) as rm:
            system = a.system or os.geteuid() == 0
            base = GLOBAL_BASE if system else DEFAULT_BASE
            target = Path(a.target) if a.target else base / rm.version
            kind = "deb" if rm.kind == media.DEB else "native"
            if system and not a.target:
                print("system install — global, world-readable, for all users:")
            print(f"Installing: {chosen.label}\n  -> {target}")
            eng = Engine(rm.root, target, make_launcher=not a.no_launcher,
                         make_desktop=not a.no_desktop, tree_only=a.tree_only,
                         version=rm.version, source_kind=kind,
                         install_deps=a.install_deps, overwrite=a.overwrite)
            return _run_install(eng, target)
    except media.MediaError as e:
        print(f"FAIL: {e}"); return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
