# retro5 — run WordPerfect 8 for Linux on a modern system

WordPerfect 8 for Linux (1997/98) is a 32-bit binary linked against **libc5**,
which no modern distribution ships. **retro5** is a small `libc5 → glibc`
shim (`retro5.so`) plus a byte-level *retargeter* that makes those ancient
binaries load and run against today's glibc — no chroot, no container, no
recompiled libc5.

This release bundles everything you need, in two flavours depending on where
you're starting from. **Read "Which one do I use?" first.**

---

## Which one do I use?

| | **A. Convert an existing install** | **B. Fresh install from your media** |
|---|---|---|
| Script | `retro5-setup.sh` | `installer/wp8_installer.py` |
| Start from | a WP tree already on disk | a WP CD / ISO / `.deb` you own |
| Installs WordPerfect? | **No** — converts a tree you already have | **Yes** — lays down a clean tree |
| Typical root | `/usr/lib/wp8` (from `wp81in.sh`) | `~/.local/share/wordperfect/<ver>` or `/opt/wordperfect8` |
| Side-by-side versions | n/a (operates on the tree you point it at) | yes (`8.0` and `8.1` coexist) |
| Makes a launcher / menu entry | no (keeps your existing one) | yes |
| Needs root | yes (writes under the tree + system lib dir) | only for a system (`/opt`) install |

**If you followed the community installer at
`https://xwp8users.com/packages/wp81in.sh`** (or otherwise already have a WP
tree, e.g. at `/usr/lib/wp8`), you want **A** — it upgrades that tree in place.

**If you have your own WordPerfect media** (a disc, an ISO, or the Corel Linux
`wp-full_*.deb`) and no install yet, you want **B** — it installs from scratch.

Both apply the *same* set of fixes (below); they differ only in whether they
*install* WordPerfect or just *convert* an install you already made.

---

## A. Convert an existing install — `retro5-setup.sh`

For a tree already on disk (default root `/usr/lib/wp8`):

```bash
sudo ./retro5-setup.sh                # defaults to /usr/lib/wp8
sudo ./retro5-setup.sh /path/to/wp    # or point it at your tree
```

It is idempotent — safe to re-run (e.g. after dropping in a newer `retro5.so`).
It does **not** install or download WordPerfect; it operates on the tree you
give it. Steps:

1. **Retargets** every libc5 ELF32 under the tree (`retarget.py --scan`).
2. **Installs `retro5.so`** into `/usr/lib/i386-linux-gnu` + `ldconfig`, so the
   32-bit loader finds it with no `LD_LIBRARY_PATH`.
3. **Morph patch** — NOPs an out-of-bounds `strcpy` in `mor_read_entry` that
   otherwise crashes WP during as-you-type spelling/morphology.
4. **XKeysymDB** — installs the Motif virtual keysyms at libX11's hardcoded
   path so Delete / BackSpace / arrow keys work in dialog text fields.
5. **`passpost.prs`** — seeds WP's default printer resource if missing.

Note the env vars it prints at the end (`XLOCALEDIR`, `WPC`) — add them to your
launcher if it doesn't set them already. The keys fix needs **no** env change.

## B. Fresh install from your media — the installer

```bash
python3 installer/wp8_installer.py            # GUI
python3 installer/wp8_install.py --help       # CLI / advanced
```

Point it at a WordPerfect disc, an ISO, or a folder of ISOs. It discovers the
edition (native tree vs Corel Linux `.deb`), installs into a clean, side-by-side
tree, generates a launcher + menu entry, and applies all the same fixes
automatically (retarget, shim, morph patch, XKeysymDB, `passpost.prs`, runtime
resources). See `installer/README.md` for details.

---

## What's in this release

```
retro5.so          the libc5 -> glibc shim (32-bit ELF)
retarget.py        standalone retargeter (byte-edits one file or --scan a tree)
XKeysymDB          Motif/OSF virtual keysyms (dialog text-field keys)
retro5-setup.sh    approach A: convert an existing WP tree in place
installer/         approach B: install from your own media/ISO/.deb
README.md          this file
LICENSE            MIT
```

## Requirements

WordPerfect is a **32-bit (i386)** program, so on a 64-bit system you must
install the **32-bit runtime libraries** — this is the single most common reason
a freshly-retargeted `xwp` won't start (`No such file or directory` on the
loader, or a silent exit). You also need `python3` for `retarget.py` / the
installer, and root for the system-wide steps.

**What's actually needed depends on the edition:**

| Edition | 32-bit libraries required |
|---|---|
| WP 8.1 (Corel `.deb`), wplinux8 — **static X** | `libc.so.6` **only** (bundles libm + the `ld-linux.so.2` loader) |
| WP 8.0.0076 — **dynamic X** | the above **plus** `libX11.so.6`, `libXt.so.6`, `libXpm.so.4` |

If you don't know which you have, install the X libs too — they're small and
harmless. Their own 32-bit dependencies (`libXext`, `libSM`, `libICE`, `libxcb`)
are pulled in automatically.

### Debian / Ubuntu / Linux Mint (and derivatives) — `apt`

```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install libc6:i386                                 # required, all editions
# dynamic-X edition (WP 8.0.0076) also needs the 32-bit X libs:
sudo apt install libx11-6:i386 libxpm4:i386 libxt6:i386
```

> On **Ubuntu 24.04+ / Debian 13 (trixie)** the time_t transition renamed some
> packages: if `libxt6:i386` isn't found, use **`libxt6t64:i386`**. `libc6:i386`
> and `libx11-6:i386` keep their names.

### Fedora / RHEL / derivatives — `dnf`

```bash
sudo dnf install glibc.i686                                 # required, all editions
sudo dnf install libX11.i686 libXpm.i686 libXt.i686         # dynamic-X edition
```

### Arch / Manjaro — `pacman` (enable the `[multilib]` repo first)

```bash
# uncomment the [multilib] section in /etc/pacman.conf, then:
sudo pacman -S lib32-glibc                                  # required, all editions
sudo pacman -S lib32-libx11 lib32-libxpm lib32-libxt        # dynamic-X edition
```

### openSUSE — `zypper`

```bash
sudo zypper install glibc-32bit                             # required, all editions
sudo zypper install libX11-6-32bit libXpm4-32bit libXt6-32bit   # dynamic-X edition
```

`retro5-setup.sh` checks for the 32-bit loader (`/lib/ld-linux.so.2`) and stops
with the right hint if it's missing, so you'll know before WP fails to launch.

## The fixes, in one place

Whichever path you use, retro5 applies:

- **libc5 → glibc retarget** — same-length in-place edits (interpreter, the
  `libc.so.5`/`libm.so.5` `DT_NEEDED`s, hidden `errno`); the ancient `.hash`
  stays intact (unlike `patchelf`, which grows `.dynstr` and corrupts it).
- **errno bridge** in the shim — including the stat family, without which WP
  spuriously aborts every save with *"An error occurred opening the file."*
- **Morph patch** — NOPs the `mor_read_entry` OOB `strcpy` crash.
- **XKeysymDB** — restores Delete/BackSpace/arrow keys in Motif text fields.
- **`passpost.prs`** — WP's default printer resource, absent in some editions.

## Manual retargeting

`retarget.py` is self-contained if you just want the byte edits:

```bash
./retarget.py --scan /usr/lib/wp8      # convert every libc5 ELF32 under a tree
./retarget.py --backup wpbin/xwp       # one file, keeping a .preretarget copy
```

You must still put `retro5.so` on the loader path (e.g. copy it into
`/usr/lib/i386-linux-gnu` and run `ldconfig`, or set `LD_LIBRARY_PATH`).

## License & scope

MIT (see `LICENSE`). retro5 ships **no** WordPerfect code or Corel media — you
supply your own lawfully-obtained WordPerfect. `XKeysymDB` is standard
MIT-licensed X11 keysym data.
