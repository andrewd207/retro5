# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""Locate and resolve Corel WordPerfect / suite install media.

The installer accepts media as a directory *or* an ISO image, and there is more
than one packaging in the wild:

  * a **native tree** - the standalone WordPerfect 8 for Linux disc, which holds
    Corel's own `shared/ship` manifest + `linux/` tree (installed via install.wp);
  * a **.deb tree** - Corel Linux OS shipped WordPerfect 8.1 (and the rest of the
    suite) as Debian packages (`wp-full_*.deb`), which unpack to an already
    laid-out file tree.

This module hides those differences behind `resolve()`, which returns a
`ResolvedMedia` whose `.root` is a directory the engine can install from, and
`discover()`, which classifies a pile of paths (e.g. a folder full of ISOs)
without fully extracting them.

ISO reading uses whatever tool is present, no root required where possible:
  7z (extract)  ->  bsdtar (extract)  ->  fuseiso (mount)  ->  udisksctl (mount)
  ->  xorriso (extract).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# --- media "kinds" -----------------------------------------------------------
NATIVE = "native"        # Corel shared/ship + linux/ tree (install.wp pipeline)
DEB = "deb"              # Debian package(s): wp-full_*.deb etc. (retarget pipeline)
WINDOWS = "windows"      # a Windows Corel product (COREL/SUITE8 ...) - not installable
UNKNOWN = "unknown"


class MediaError(Exception):
    pass


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


# --- signatures --------------------------------------------------------------
# A native WP-for-Linux tree always has these two.
_NATIVE_MARKERS = ("shared/ship", "linux/bin")
# Debian WordPerfect/suite packages.
_DEB_GLOBS = ("wp-full", "wp-manual", "wordperfect", "quattro", "presentations",
              "corel-wp")
# Windows Corel media (specific paths only - generic SETUP.EXE/AUTORUN.INF
# would match unrelated Windows discs and mislabel them).
_WINDOWS_MARKERS = ("corel/suite8", "suite8/appman", "suite8/wpwin")


def _find_native_root(base: Path, max_depth: int = 4) -> Path | None:
    """Return the directory under `base` that holds a native WP-Linux tree."""
    base = Path(base)
    if _is_native_root(base):
        return base
    base_depth = len(base.parts)
    for dirpath, dirnames, _files in os.walk(base):
        p = Path(dirpath)
        if len(p.parts) - base_depth > max_depth:
            dirnames[:] = []
            continue
        if _is_native_root(p):
            return p
    return None


def _is_native_root(p: Path) -> bool:
    return all((p / m).exists() for m in _NATIVE_MARKERS)


# --- ISO listing / extraction (tool-agnostic) --------------------------------
def _iso_list(iso: Path) -> list[str]:
    """Return member paths inside an ISO (best-effort, forward-slashed)."""
    if _have("7z"):
        r = subprocess.run(["7z", "l", "-slt", str(iso)],
                           capture_output=True, text=True)
        names = []
        for line in r.stdout.splitlines():
            if line.startswith("Path = "):
                names.append(line[7:].replace("\\", "/"))
        # drop the archive's own path (first Path = line)
        return names[1:] if names else names
    if _have("isoinfo"):
        r = subprocess.run(["isoinfo", "-f", "-i", str(iso)],
                           capture_output=True, text=True)
        return [ln.lstrip("/").replace("\\", "/") for ln in r.stdout.splitlines()]
    if _have("bsdtar"):
        r = subprocess.run(["bsdtar", "-tf", str(iso)],
                           capture_output=True, text=True)
        return r.stdout.splitlines()
    raise MediaError("no ISO reader available (install p7zip, libarchive-tools, "
                     "or genisoimage)")


def _iso_extract(iso: Path, dest: Path, subpaths: list[str] | None = None) -> None:
    """Extract `iso` (optionally only `subpaths`) into `dest`."""
    dest.mkdir(parents=True, exist_ok=True)
    if _have("7z"):
        cmd = ["7z", "x", "-y", f"-o{dest}", str(iso)]
        if subpaths:
            cmd += subpaths
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode == 0:
            return
        # fall through to other tools on failure
    if _have("bsdtar"):
        cmd = ["bsdtar", "-x", "-C", str(dest), "-f", str(iso)]
        if subpaths:
            cmd += subpaths
        if subprocess.run(cmd, capture_output=True, text=True).returncode == 0:
            return
    # mount-based fallbacks copy the whole tree
    mp = _iso_mount(iso)
    if mp:
        try:
            for name in os.listdir(mp):
                s = Path(mp) / name
                d = dest / name
                if s.is_dir():
                    shutil.copytree(s, d, dirs_exist_ok=True)
                else:
                    shutil.copy2(s, d)
        finally:
            _iso_umount(iso, mp)
        return
    raise MediaError(f"could not extract {iso.name} with any available tool")


_MOUNTS: dict[str, str] = {}


def _iso_mount(iso: Path) -> str | None:
    if _have("fuseiso"):
        mp = tempfile.mkdtemp(prefix="wpmedia-mnt-")
        if subprocess.run(["fuseiso", str(iso), mp],
                          capture_output=True, text=True).returncode == 0:
            _MOUNTS[str(iso)] = ("fuseiso", mp)
            return mp
        os.rmdir(mp)
    if _have("udisksctl"):
        r = subprocess.run(["udisksctl", "loop-setup", "-r", "-f", str(iso)],
                           capture_output=True, text=True)
        # udisks auto-mounts; parse the mount point from a follow-up call is
        # fiddly, so we leave this as a last resort and let extract handle it.
    return None


def _iso_umount(iso: Path, mp: str) -> None:
    kind_mp = _MOUNTS.pop(str(iso), None)
    if kind_mp and kind_mp[0] == "fuseiso":
        subprocess.run(["fusermount", "-u", mp], capture_output=True)
        try:
            os.rmdir(mp)
        except OSError:
            pass


# --- classification ----------------------------------------------------------
def _classify_names(names: list[str]) -> tuple[str, list[str]]:
    """Given member names, return (kind, deb_members)."""
    low = [n.lower() for n in names]
    if any(n.endswith("shared/ship") or n == "shared/ship" for n in low) and \
       any("linux/bin" in n for n in low):
        return NATIVE, []
    debs = [orig for orig, n in zip(names, low)
            if n.endswith(".deb") and any(g in os.path.basename(n) for g in _DEB_GLOBS)]
    if debs:
        return DEB, debs
    if any(any(m.lower() in n for m in _WINDOWS_MARKERS) for n in low):
        return WINDOWS, []
    return UNKNOWN, []


@dataclass
class Candidate:
    path: Path                 # the ISO file or directory the user pointed at
    kind: str                  # NATIVE / DEB / WINDOWS / UNKNOWN
    label: str                 # human label ("WordPerfect 8.0 (ISO)")
    version: str = "8"         # "8.0" / "8.1" — used for side-by-side install dirs
    deb_members: list[str] = field(default_factory=list)

    @property
    def installable(self) -> bool:
        return self.kind in (NATIVE, DEB)


def _deb_version(debs: list[str]) -> str:
    """wp-full_8.1-12_i386.deb -> '8.1'."""
    for d in debs:
        b = os.path.basename(d)
        if b.startswith("wp-full") or b.startswith("wordperfect"):
            parts = b.split("_")
            if len(parts) > 1:
                return parts[1].split("-")[0]
    return "8.1"


def _label_for(path: Path, kind: str, version: str) -> str:
    name = path.name
    if kind == NATIVE:
        return f"WordPerfect {version} (native disc) — {name}"
    if kind == DEB:
        return f"WordPerfect {version} suite (Debian packages) — {name}"
    if kind == WINDOWS:
        return f"Corel (Windows product, not installable) — {name}"
    return f"Unrecognized media — {name}"


def _find_debs(root: Path, maxdepth: int = 8) -> list[str]:
    """Recursively find WordPerfect .deb files under root, tolerating unreadable
    directories. A plain Path.rglob aborts the whole scan the moment it steps
    into a flaky mount (e.g. a VirtualBox Guest Additions CD raising
    'OSError: [Errno 5] Input/output error') — so walk with os.walk(onerror=…)
    which just skips a directory it can't read. Depth-bounded so scanning a
    broad root like /media doesn't wander the entire filesystem."""
    root = str(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        if dirpath.count(os.sep) - base_depth >= maxdepth:
            dirnames[:] = []                     # stop descending past maxdepth
        for n in filenames:
            if n.endswith(".deb") and any(g in n for g in _DEB_GLOBS):
                found.append(os.path.join(dirpath, n))
    return found


def classify(path: Path) -> Candidate:
    """Classify a single path (ISO or directory) without full extraction."""
    path = Path(path)
    if path.is_dir():
        if _find_native_root(path):
            return Candidate(path, NATIVE, _label_for(path, NATIVE, "8.0"), "8.0")
        debs = _find_debs(path)
        if debs:
            v = _deb_version(debs)
            return Candidate(path, DEB, _label_for(path, DEB, v), v, debs)
        return Candidate(path, UNKNOWN, _label_for(path, UNKNOWN, "8"))
    if path.suffix.lower() == ".iso":
        names = _iso_list(path)
        kind, debs = _classify_names(names)
        # the standalone WordPerfect-for-Linux disc is 8.0; the Corel Linux OS
        # packages are 8.1 (read from the .deb filename).
        version = _deb_version(debs) if kind == DEB else ("8.0" if kind == NATIVE else "8")
        return Candidate(path, kind, _label_for(path, kind, version), version, debs)
    return Candidate(path, UNKNOWN, _label_for(path, UNKNOWN, "8"))


def discover(paths: list[Path]) -> list[Candidate]:
    """Classify every ISO/dir given, or every ISO inside a given directory."""
    out: list[Candidate] = []
    for p in paths:
        p = Path(p)
        if p.is_dir() and not _find_native_root(p):
            # a directory that isn't itself a native root: scan it for ISOs
            isos = sorted(p.glob("*.iso"))
            if isos:
                for iso in isos:
                    try:
                        out.append(classify(iso))
                    except MediaError:
                        out.append(Candidate(iso, UNKNOWN, _label_for(iso, UNKNOWN, [])))
                continue
        out.append(classify(p))
    return out


# --- resolution --------------------------------------------------------------
@dataclass
class ResolvedMedia:
    root: Path                 # directory the engine installs from
    kind: str
    label: str
    version: str = "8"         # "8.0" / "8.1"
    _tmp: str | None = None    # temp dir to clean up, if any

    def close(self) -> None:
        if self._tmp and os.path.isdir(self._tmp):
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def resolve(path: Path, workdir: Path | None = None) -> ResolvedMedia:
    """Turn a user-supplied path (ISO or dir) into an installable ResolvedMedia.

    For a native tree this is the tree directory (extracted from the ISO if
    needed). For a .deb source the packages are unpacked into a staging tree.
    """
    cand = classify(path)
    if not cand.installable:
        raise MediaError(f"{path} is not installable WordPerfect-for-Linux media "
                         f"({cand.label})")

    if cand.kind == NATIVE and Path(path).is_dir():
        root = _find_native_root(Path(path))
        return ResolvedMedia(root, NATIVE, cand.label, cand.version)

    tmp = tempfile.mkdtemp(prefix="wpmedia-", dir=str(workdir) if workdir else None)

    if cand.kind == NATIVE:                      # native tree inside an ISO
        _iso_extract(Path(path), Path(tmp))
        root = _find_native_root(Path(tmp))
        if not root:
            shutil.rmtree(tmp, ignore_errors=True)
            raise MediaError(f"native tree not found after extracting {path}")
        return ResolvedMedia(root, NATIVE, cand.label, cand.version, tmp)

    # DEB: pull the packages out (from ISO or dir) and dpkg-deb -x them.
    debroot = Path(tmp) / "root"
    debroot.mkdir(parents=True, exist_ok=True)
    debs = _stage_debs(Path(path), cand, Path(tmp))
    if not debs:
        shutil.rmtree(tmp, ignore_errors=True)
        raise MediaError(f"no WordPerfect .deb packages extracted from {path}")
    for deb in debs:
        _deb_extract(deb, debroot)
    # the packages install to e.g. usr/lib/wp8/ — hand the engine that tree, the
    # dir that actually holds wpbin/xwp + shbin10.
    wproot = _find_deb_wproot(debroot)
    if not wproot:
        shutil.rmtree(tmp, ignore_errors=True)
        raise MediaError(f"WordPerfect tree (wpbin/xwp) not found in {cand.label}")
    return ResolvedMedia(wproot, DEB, cand.label, cand.version, tmp)


def _find_deb_wproot(debroot: Path, max_depth: int = 6) -> Path | None:
    """Find the installed WP tree inside an unpacked .deb (holds wpbin/xwp)."""
    base_depth = len(debroot.parts)
    for dirpath, dirnames, _files in os.walk(debroot):
        p = Path(dirpath)
        if len(p.parts) - base_depth > max_depth:
            dirnames[:] = []
            continue
        if (p / "wpbin/xwp").exists() and (p / "shbin10").is_dir():
            return p
    return None


def _stage_debs(path: Path, cand: Candidate, tmp: Path) -> list[Path]:
    if path.is_dir():
        return [Path(d) for d in cand.deb_members]
    # ISO: extract just the .deb members
    _iso_extract(path, tmp / "iso", cand.deb_members)
    found = []
    for d in cand.deb_members:
        cand_path = tmp / "iso" / d
        if cand_path.exists():
            found.append(cand_path)
        else:  # extractor may have flattened; search by basename
            base = os.path.basename(d)
            hits = list((tmp / "iso").rglob(base))
            if hits:
                found.append(hits[0])
    return found


def _deb_extract(deb: Path, dest: Path) -> None:
    if _have("dpkg-deb"):
        r = subprocess.run(["dpkg-deb", "-x", str(deb), str(dest)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
    # portable fallback: ar x <deb> && tar x data.tar.*
    if _have("ar"):
        work = Path(tempfile.mkdtemp(prefix="deb-", dir=str(dest.parent)))
        subprocess.run(["ar", "x", str(deb)], cwd=work, capture_output=True)
        for data in work.glob("data.tar*"):
            subprocess.run(["tar", "-xf", str(data), "-C", str(dest)],
                          capture_output=True)
        shutil.rmtree(work, ignore_errors=True)
        return
    raise MediaError(f"cannot extract {deb.name} (need dpkg-deb or ar+tar)")
