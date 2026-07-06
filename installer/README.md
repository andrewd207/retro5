# WordPerfect 8 — zero-to-installed installer

User-local, **no root**. Installs WP8 from the original Corel media using the
`retro5.so` libc5→glibc shim, and fixes every gap we hit by hand.

## Run

GUI (GTK4 wizard):

```sh
python3 wp8_installer.py
sh install-desktop.sh      # add "Install WordPerfect 8" to your app menu
```

The Options page has an **"Install for all users (system-wide)"** checkbox — it
targets `/opt/wordperfect8` and elevates the **whole** install with **`pkexec`** (the
desktop-standard polkit password prompt). As root it lays down a world-readable tree,
a system launcher `/usr/local/bin/xwp`, and a menu entry in
`/usr/share/applications/`; each user's `~/.wprc` self-seeds on first run. Unchecked =
user-local under `~/.local`, no root. (The engine auto-detects system vs user from the
target path.)

CLI (same engine, scriptable):

```sh
python3 wp8_install.py --target ~/.local/share/wordperfect8   # full user install
python3 wp8_install.py --complete /usr/wplinux                # repair an existing tree
python3 wp8_install.py --tree-only --target /opt/wordperfect8 # root half of a system install
python3 wp8_install.py --help
```

The generated launcher **self-seeds** `~/.wprc/.wpc8x.set` on first run, so a
system-wide install works for every user with no per-user steps.

Then launch WordPerfect:

```sh
~/.local/bin/xwp                 # add -fontSize 20 for bigger menus
```

## What it does (`wp8_install.Engine`)

1. **Prerequisites** — media check, 32-bit loader, build `wpdecom2`, locate `retro5.so`.
2. **Install files** — parse `shared/ship`, decompress/copy every entry, **plus**:
   - the 60 `wp60*.us.all` printer drivers (`build-tree.sh` skipped `prn/gu`);
   - the `arch*` **`wxar` archives** (`archpfb`/`archafm`/`archbdf`/`archpcf`, and
     the macro/learn archives) — the native installer's `a`(rchive) type, which
     is where **all the Type1 fonts live** (`Helve-WP`/`Courier-WP`/`Roman-WP` +
     variants). `build-tree.sh` skipped these, which is why fonts were missing.
   - supplementary WP faces from the standalone `fonts/` dir.
   `.drs`/`.lrs` and the fonts are laid down **verbatim, never decompressed**.
3. **Retarget** — `ld.so.1→2`, `libc.so.5→retro5.so`, `libm.so.5→6`, and mark the
   non-TLS `errno` `STV_HIDDEN` (leaves `_errno` exported — the errno bridge).
4. **Patches** — the morpher typing-crash fix, **byte-guarded**: only NOPs the dead
   OOB `strcpy` if the exact original bytes are present (never re-patches / never
   touches a different build).
5. **Permissions** — guarantees owner read+write on every file, so WP's
   `access(R_OK|W_OK)` config probes can't raise "File IO Error".
6. **Runtime config** — install the shim into `shbin10`; write a **valid empty**
   `.wpc.admin` (a real WPC record file, not the 0-byte stub `build-tree.sh` left).
7. **Launcher** — `~/.local/bin/xwp` wrapper (sets `WPC`, `LD_LIBRARY_PATH`,
   **`XLOCALEDIR`** — the locale fix that stops the startup SIGSEGV) + a `.desktop`.
8. **Per-user setup** — seed `~/.wprc/.wpc8x.set` so first-run startup doesn't error.

## Opening documents / single instance

WP8 is **single-instance per X display**. When WordPerfect is already running,
`xwp file.wpd` does **not** start a second copy — xwp detects the running instance
(the `WP8ISRUNNING` X property), sets the `WP60FILENAME` property on its window, pokes
it, and exits, so the **running** WordPerfect opens the file. So to open a document in
the existing WP, just run `xwp <file>` (or double-click a `.wpd`). `xwp` with no file
while running is a no-op. `xwp -macro <name>` plays a PerfectScript macro on launch
(e.g. a `FileNew`/`FileOpen` macro).

## Uninstalling

- **Menu:** an **"Uninstall WordPerfect 8"** entry is installed next to the launcher;
  it opens the wizard straight into the uninstall confirmation (elevates via `pkexec`
  for a system install). The installer scripts are embedded in `<root>/installer/` so
  this works even if the original checkout is gone.
- **CLI:** `python3 wp8_install.py --uninstall <root> [--remove-profile]` — removes the
  tree + its launcher/menu entries; keeps `~/.wprc` and your documents unless
  `--remove-profile`. Refuses to delete anything that isn't a WP8 install.

## Notes

- **File locking** works through the shim (WP's `fcntl` locks return 0); no need to
  disable it. Only turn it off (Preferences ▸ File Locking) if `~` is on NFS and you
  see spurious "file in use" dialogs.
- **Fonts** are fully on the media — packed in the `wxar` archives `linux/dat/archpfb`
  (`.pfb`) and `archafm` (`.afm`). The installer unpacks them (41 `.pfb` total,
  matching a stock install), so no external `fonts-16.deb` is needed. The `wxar`
  format is trivial: `<name>\n<size>\n<size bytes>`, repeated (`extract_wxar`).
- Everything lands under the target dir + `~/.local` + `~/.wprc`; nothing needs sudo.
