#!/usr/bin/env python3
# wpprinter-dialog.py — GTK4 "Select/Add Printer" dialog for WordPerfect 8.
# SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
#
# The modern replacement for WP's printer-select UI: list the *CUPS* queues (not
# WP .all drivers), let the user pick which one WP's Passthru-PostScript printer
# targets, and record it via the C `wpselect` tool (writes $WPCOM/wpsink.dest,
# which wpsink adopts -> `lp -d NAME`). "Add Printer…" hands off to the CUPS
# admin. No per-printer .prs is minted — see README "Printer model".
#
# Runs standalone now (against the mock/live CUPS); the selection-side IPC to
# xwp (tell it the current printer changed) plugs in once captured.
import os, sys, shutil, subprocess, ctypes
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gio


def make_transient_x11(gtk_window, parent_xid):
    """Parent our window to WordPerfect's window on the X server, the way the
    real xwpdest does (XSetTransientForHint). WP is an X11/Motif app — on a
    Wayland desktop it runs under XWayland, and we run under XWayland too
    (GDK_BACKEND=x11), so both share one X server and the X window id is valid.
    A native Wayland client could NOT do this (no cross-client parenting), which
    is exactly why the drop-in forces the X11 backend. Best-effort; no-op if we
    somehow aren't on X11."""
    try:
        surface = gtk_window.get_surface()
        # only GdkX11Surface has get_xid()
        get_xid = getattr(surface, "get_xid", None)
        if not get_xid:
            return False
        our_xid = get_xid()
        x11 = ctypes.CDLL("libX11.so.6")
        dpy = x11.XOpenDisplay(None)
        if not dpy:
            return False
        x11.XSetTransientForHint(dpy, ctypes.c_ulong(our_xid), ctypes.c_ulong(parent_xid))
        x11.XFlush(dpy)
        x11.XCloseDisplay(dpy)
        return True
    except Exception as e:
        print(f"wpprinter-dialog: transient-for failed: {e}", file=sys.stderr)
        return False


def launch_printer_config():
    """Open the system's EXISTING printer configuration UI — adding printers and
    setting per-printer paper/tray/quality defaults is CUPS/desktop territory,
    not ours. Try the common tools, fall back to the CUPS web admin."""
    for tool in ("system-config-printer", "gnome-control-center"):
        if shutil.which(tool):
            args = [tool, "printers"] if tool == "gnome-control-center" else [tool]
            subprocess.Popen(args)
            return tool
    Gio.AppInfo.launch_default_for_uri("http://localhost:631/admin", None)
    return "CUPS web admin"

HERE = os.path.dirname(os.path.abspath(__file__))
WPSELECT = os.path.join(HERE, "wpselect")


def wpselect(*args):
    """Call the C wpselect tool; return (rc, stdout)."""
    exe = WPSELECT if os.access(WPSELECT, os.X_OK) else None
    if not exe:
        return 127, ""
    p = subprocess.run([exe, *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def list_printers():
    """[(name, is_default)] from `wpselect --list`."""
    rc, out = wpselect("--list")
    printers = []
    for line in out.splitlines():
        if line.startswith("  "):
            row = line.strip()
            is_def = row.endswith("[default]")
            name = row.replace("[default]", "").strip()
            printers.append((name, is_def))
    return printers


def current_dest():
    rc, out = wpselect("--get")
    return out if out and not out.startswith("(") else None


def printer_summary(name):
    """Read-only 'paper=A4 tray=Auto type=plain' from CUPS (via wpselect --info)."""
    rc, out = wpselect("--info", name)
    return out or ""


class PrinterDialog(Gtk.ApplicationWindow):
    def __init__(self, app, parent_xid=0):
        super().__init__(application=app, title="WordPerfect — Select Printer")
        self.set_default_size(440, 360)
        self.parent_xid = parent_xid
        if parent_xid:
            self.set_modal(True)                       # GTK-level modality
            self.connect("map", self._on_map)          # X11 transient once mapped

    def _on_map(self, _w):
        if self.parent_xid:
            make_transient_x11(self, self.parent_xid)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(16); box.set_margin_bottom(16)
        box.set_margin_start(16); box.set_margin_end(16)
        self.set_child(box)

        heading = Gtk.Label(xalign=0)
        heading.set_markup("<b>Choose the printer WordPerfect prints to</b>")
        box.append(heading)
        sub = Gtk.Label(xalign=0, wrap=True)
        sub.set_text("WordPerfect sends PostScript to the CUPS printer you pick here. "
                     "Adding printers and setting their paper/tray/quality defaults is "
                     "done in the system’s printer settings (button below).")
        sub.add_css_class("dim-label")
        box.append(sub)

        scroller = Gtk.ScrolledWindow(vexpand=True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroller.set_child(self.listbox)
        box.append(scroller)
        self.listbox.connect("row-selected", self.on_row_selected)

        self.caps = Gtk.Label(xalign=0, wrap=True)      # read-only CUPS defaults
        self.caps.add_css_class("dim-label")
        box.append(self.caps)

        self.status = Gtk.Label(xalign=0)
        self.status.add_css_class("dim-label")
        box.append(self.status)

        btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btns.set_halign(Gtk.Align.END)
        cfg_btn = Gtk.Button(label="Configure Printers…")
        cfg_btn.connect("clicked", self.on_configure)
        set_btn = Gtk.Button(label="Set as WordPerfect Printer")
        set_btn.add_css_class("suggested-action")
        set_btn.connect("clicked", self.on_set)
        btns.append(cfg_btn)
        btns.append(set_btn)
        box.append(btns)

        self.reload()

    def on_row_selected(self, _lb, row):
        if row is None:
            self.caps.set_text("")
            return
        s = printer_summary(row.printer_name)
        self.caps.set_text(f"{row.printer_name} defaults — {s}" if s
                           else f"{row.printer_name}: (using CUPS defaults)")

    def reload(self):
        child = self.listbox.get_first_child()
        while child:
            nxt = child.get_next_sibling()
            self.listbox.remove(child)
            child = nxt
        printers = list_printers()
        cur = current_dest()
        if not printers:
            self.status.set_text("No CUPS printers found. Click “Add Printer…” to set one up.")
        for name, is_def in printers:
            row = Gtk.ListBoxRow()
            row.printer_name = name
            r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            r.set_margin_top(8); r.set_margin_bottom(8)
            r.set_margin_start(8); r.set_margin_end(8)
            lbl = Gtk.Label(label=name, xalign=0, hexpand=True)
            r.append(lbl)
            tags = []
            if is_def: tags.append("system default")
            if cur and name == cur: tags.append("✓ WordPerfect")
            if tags:
                t = Gtk.Label(label="   ".join(tags))
                t.add_css_class("dim-label")
                r.append(t)
            row.set_child(r)
            self.listbox.append(row)
            if cur and name == cur:
                self.listbox.select_row(row)
        if cur:
            self.status.set_text(f"WordPerfect currently prints to: {cur}")

    def on_set(self, _btn):
        row = self.listbox.get_selected_row()
        if not row:
            self.status.set_text("Select a printer first.")
            return
        rc, out = wpselect("--set", row.printer_name)
        if rc == 0:
            self.status.set_text(f"WordPerfect will now print to: {row.printer_name}")
            self.reload()
        else:
            self.status.set_text("Could not set the printer (is wpselect built?).")

    def on_configure(self, _btn):
        # adding printers + per-printer defaults live in the system's own tool
        tool = launch_printer_config()
        self.status.set_text(f"Opened {tool}. Add or configure a printer there, "
                             "then it'll appear in this list.")


def _parse_parent_xid(argv):
    """Parent window id: --parent-xid, then $WPPARENT / $WINDOWID. Accept hex
    (0x..) or decimal. (Exactly how WP delivers its CLIENT_WINDOW id to xwpdest
    — argv vs the selection socket — is confirmed by capture-print-traffic.sh;
    the drop-in passes whatever it can find until then.)"""
    val = None
    for i, a in enumerate(argv):
        if a == "--parent-xid" and i + 1 < len(argv):
            val = argv[i + 1]
    if val is None:
        val = os.environ.get("WPPARENT") or os.environ.get("WINDOWID")
    if not val:
        return 0
    try:
        return int(val, 16) if val.lower().startswith("0x") else int(val)
    except ValueError:
        return 0


class App(Gtk.Application):
    def __init__(self, parent_xid=0):
        super().__init__(application_id="com.retro5.wpprinter")
        self.parent_xid = parent_xid

    def do_activate(self):
        PrinterDialog(self, self.parent_xid).present()


if __name__ == "__main__":
    xid = _parse_parent_xid(sys.argv)
    # Gtk.Application chokes on unknown argv; run with a clean one.
    sys.exit(App(xid).run([sys.argv[0]]))
