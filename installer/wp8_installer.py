#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andrew Haines
"""wp8_installer.py - GTK4 wizard front-end for wp8_install.Engine.

Zero-to-installed WordPerfect 8 (user-local, no root). Three pages:
  Welcome -> Options (media/target) -> Progress -> Done.
The engine runs in a worker thread; steps stream back to the UI.

Run:  python3 wp8_installer.py
"""
import subprocess
import sys
import threading
from pathlib import Path

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gio, Gdk, GObject

from wp8_install import Engine, Step, DEFAULT_TARGET
import media as mediamod


CSS = b"""
.title { font-size: 22px; font-weight: 800; }
.subtitle { color: alpha(@theme_fg_color, 0.65); }
.steprow { padding: 4px 2px; }
.ok   { color: #2ea043; font-weight: 700; }
.fail { color: #f85149; font-weight: 700; }
.mono { font-family: monospace; font-size: 11px; }
.card { background: alpha(@theme_fg_color,0.04); border-radius: 10px; padding: 14px; }
"""


class Installer(Gtk.Application):
    def __init__(self, uninstall_mode=False):
        super().__init__(application_id="com.wp8.installer",
                         flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.uninstall_mode = uninstall_mode

    def do_activate(self):
        prov = Gtk.CssProvider(); prov.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), prov, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        self.win = Gtk.ApplicationWindow(application=self, title="WordPerfect 8 Installer")
        self.win.set_default_size(680, 560)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT)
        self.win.set_child(self.stack)
        self._build_welcome(); self._build_options(); self._build_progress(); self._build_done()
        self.stack.set_visible_child_name("welcome")
        self.win.present()
        # launched from the "Uninstall WordPerfect 8" menu entry -> go straight to it
        if self.uninstall_mode:
            found = self._find_installs()
            if found:
                self._start_uninstall(found[0])
            else:
                self.done_title.set_text("Nothing to uninstall")
                self.done_title.remove_css_class("fail")
                self.done_body.set_text("No WordPerfect 8 install was found.")
                self.launch_btn.set_visible(False)
                self.stack.set_visible_child_name("done")

    # ---- pages -----------------------------------------------------------
    def _page(self, name):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                    margin_top=28, margin_bottom=24, margin_start=32, margin_end=32)
        self.stack.add_named(b, name)
        return b

    def _heading(self, box, title, subtitle):
        t = Gtk.Label(label=title, xalign=0); t.add_css_class("title")
        s = Gtk.Label(label=subtitle, xalign=0, wrap=True); s.add_css_class("subtitle")
        box.append(t); box.append(s)

    def _build_welcome(self):
        b = self._page("welcome")
        self._heading(b, "WordPerfect 8 for Linux",
                      "Installs from the original Corel media using the retro5 "
                      "shim — user-local, no root required.")
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6); card.add_css_class("card")
        for line in ("•  Decompresses the WP tree + 60 printer drivers",
                     "•  Retargets libc5 → glibc and applies the morpher crash fix",
                     "•  Fixes config permissions and seeds a valid profile",
                     "•  Creates a launcher (~/.local/bin/xwp) + desktop entry"):
            card.append(Gtk.Label(label=line, xalign=0))
        b.append(card)
        b.append(Gtk.Box(vexpand=True))
        nav = Gtk.Box(spacing=8)
        found = self._find_installs()
        if found:
            unb = Gtk.Button(label="Uninstall…"); unb.add_css_class("destructive-action")
            unb.connect("clicked", lambda *_: self._start_uninstall(found[0]))
            nav.append(unb)
        nav.append(Gtk.Box(hexpand=True))
        nxt = Gtk.Button(label="Continue"); nxt.add_css_class("suggested-action")
        nxt.connect("clicked", lambda *_: self.stack.set_visible_child_name("options"))
        nav.append(nxt); b.append(nav)

    @staticmethod
    def _find_installs():
        cands = [Path("/opt/wordperfect8"), Path.home() / ".local/share/wordperfect8",
                 Path("/usr/wplinux")]
        return [p for p in cands if (p / "shlib10").is_dir() or (p / "wpbin/xwp").exists()]

    @staticmethod
    def _is_system_path(p):
        try:
            Path(p).resolve().relative_to(Path.home().resolve()); return False
        except ValueError:
            return True

    def _start_uninstall(self, target):
        dlg = Gtk.AlertDialog()
        dlg.set_message(f"Uninstall WordPerfect 8 from {target}?")
        dlg.set_detail("Removes the install tree, its launcher and menu entry. Your "
                       "~/.wprc profile and your documents are kept."
                       + ("\n\nThis needs your admin password." if self._is_system_path(target) else ""))
        dlg.set_buttons(["Cancel", "Uninstall"])
        dlg.set_cancel_button(0); dlg.set_default_button(1)
        dlg.choose(self.win, None, self._on_uninstall_confirm, target)

    def _on_uninstall_confirm(self, dlg, res, target):
        try:
            idx = dlg.choose_finish(res)
        except Exception:  # noqa - dismissed
            return
        if idx != 1:
            return
        self.stack.set_visible_child_name("progress")
        threading.Thread(target=self._uninstall_worker,
                         args=(target, self._is_system_path(target)), daemon=True).start()

    def _uninstall_worker(self, target, system):
        if system:
            GLib.idle_add(self._on_step,
                          Step("elevate", "Requesting admin access (pkexec)...", 0.1, ok=True))
            engine_py = str(Path(__file__).with_name("wp8_install.py"))
            p = subprocess.run(["pkexec", sys.executable, engine_py, "--uninstall", str(target)],
                               capture_output=True, text=True)
            log = [l.strip() for l in p.stdout.splitlines() if l.strip()]
            ok = (p.returncode == 0)
            GLib.idle_add(self._on_step, Step(
                "uninstall", "Uninstalled (elevated)" if ok else "Uninstall failed", 1.0,
                ok=ok, detail="" if ok else (p.stderr or "cancelled/denied").strip()[:300], log=log))
        else:
            eng = Engine(Path(target), target=Path(target))   # media unused for uninstall
            try:
                log = eng.uninstall(Path(target))
                GLib.idle_add(self._on_step, Step("uninstall", "Uninstalled", 1.0, ok=True, log=log))
                ok = True
            except Exception as e:  # noqa
                GLib.idle_add(self._on_step, Step("uninstall", "Uninstall failed", 1.0,
                                                  ok=False, detail=str(e)))
                ok = False
        GLib.idle_add(self._on_finish, ok, {"uninstalled": str(target)}, target)

    def _build_options(self):
        b = self._page("options")
        self._heading(b, "Options", "Confirm the source media and where to install.")
        grid = Gtk.Grid(row_spacing=10, column_spacing=10)
        self.media_entry = Gtk.Entry(hexpand=True)
        self.media_entry.set_placeholder_text("an ISO, an extracted tree, or a folder of ISOs")
        detect = Gtk.Button(label="Detect versions")
        detect.connect("clicked", self._on_detect)
        self.version_dd = Gtk.DropDown.new_from_strings(["(press Detect versions)"])
        self.version_dd.set_sensitive(False)
        self.version_dd.connect("notify::selected", self._on_version_changed)
        self._candidates = []          # installable media.Candidate objects
        self.target_entry = Gtk.Entry(text=str(DEFAULT_TARGET), hexpand=True)
        grid.attach(Gtk.Label(label="Install media:", xalign=0), 0, 0, 1, 1)
        grid.attach(self.media_entry, 1, 0, 1, 1)
        grid.attach(detect, 2, 0, 1, 1)
        grid.attach(Gtk.Label(label="Version:", xalign=0), 0, 1, 1, 1)
        grid.attach(self.version_dd, 1, 1, 2, 1)
        grid.attach(Gtk.Label(label="Install to:", xalign=0), 0, 2, 1, 1)
        grid.attach(self.target_entry, 1, 2, 2, 1)
        b.append(grid)
        self.launcher_chk = Gtk.CheckButton(label="Create launcher (~/.local/bin/xwp)", active=True)
        b.append(self.launcher_chk)
        self.desktop_chk = Gtk.CheckButton(label="Add WordPerfect to the applications menu", active=True)
        b.append(self.desktop_chk)
        self.launcher_chk.bind_property("active", self.desktop_chk, "sensitive",
                                        GObject.BindingFlags.SYNC_CREATE)
        self.system_chk = Gtk.CheckButton(
            label="Install for all users (system-wide — asks for your admin password)")
        self.system_chk.connect("toggled", self._on_system_toggled)
        b.append(self.system_chk)
        self.opt_status = Gtk.Label(xalign=0, wrap=True); self.opt_status.add_css_class("subtitle")
        b.append(self.opt_status)
        b.append(Gtk.Box(vexpand=True))
        nav = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        back = Gtk.Button(label="Back")
        back.connect("clicked", lambda *_: self.stack.set_visible_child_name("welcome"))
        inst = Gtk.Button(label="Install"); inst.add_css_class("suggested-action")
        inst.connect("clicked", self._start_install)
        nav.append(back); nav.append(inst); b.append(nav)

    def _build_progress(self):
        b = self._page("progress")
        self._heading(b, "Installing…", "This takes a minute; the WP tree is being decompressed.")
        self.bar = Gtk.ProgressBar(show_text=True); b.append(self.bar)
        self.steps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        sw = Gtk.ScrolledWindow(vexpand=True); sw.set_child(self.steps_box)
        sw.add_css_class("card")
        b.append(sw)

    def _build_done(self):
        b = self._page("done")
        self.done_title = Gtk.Label(xalign=0); self.done_title.add_css_class("title")
        b.append(self.done_title)
        self.done_body = Gtk.Label(xalign=0, wrap=True, selectable=True)
        b.append(self.done_body)
        self.done_log = Gtk.Label(xalign=0, wrap=True, selectable=True); self.done_log.add_css_class("mono")
        sw = Gtk.ScrolledWindow(vexpand=True); sw.set_child(self.done_log); sw.add_css_class("card")
        b.append(sw)
        nav = Gtk.Box(spacing=8, halign=Gtk.Align.END)
        self.launch_btn = Gtk.Button(label="Launch WordPerfect"); self.launch_btn.add_css_class("suggested-action")
        self.launch_btn.connect("clicked", self._launch)
        close = Gtk.Button(label="Close"); close.connect("clicked", lambda *_: self.win.close())
        nav.append(close); nav.append(self.launch_btn); b.append(nav)

    # ---- run -------------------------------------------------------------
    def _on_system_toggled(self, chk):
        # re-version the target under the right base (/opt vs ~/.local)
        if self._candidates and 0 <= self.version_dd.get_selected() < len(self._candidates):
            self._on_version_changed()
        elif chk.get_active():
            self._user_target = self.target_entry.get_text()
            self.target_entry.set_text("/opt/wordperfect")
        else:
            self.target_entry.set_text(getattr(self, "_user_target", str(DEFAULT_TARGET)))

    def _on_detect(self, _btn):
        path = self.media_entry.get_text().strip()
        if not path:
            self.opt_status.set_text("⚠  Enter a path to an ISO or a folder of ISOs first.")
            return
        self.opt_status.set_text("Scanning media…")
        threading.Thread(target=self._detect_worker, args=(path,), daemon=True).start()

    def _detect_worker(self, path):
        try:
            cands = mediamod.discover([Path(path)])
        except Exception as e:  # noqa
            GLib.idle_add(self._populate_versions, [], str(e)); return
        GLib.idle_add(self._populate_versions,
                      [c for c in cands if c.installable], None)

    def _populate_versions(self, installable, err):
        self._candidates = installable
        if err:
            self.version_dd.set_sensitive(False)
            self.opt_status.set_text(f"⚠  {err}")
            return
        if not installable:
            self.version_dd.set_model(Gtk.StringList.new(["(no WordPerfect media found)"]))
            self.version_dd.set_sensitive(False)
            self.opt_status.set_text("No installable WordPerfect-for-Linux media found there.")
            return
        self.version_dd.set_model(Gtk.StringList.new([c.label for c in installable]))
        self.version_dd.set_sensitive(True)
        self.opt_status.set_text(f"Found {len(installable)} installable version(s).")

    def _version_base(self):
        return Path("/opt/wordperfect") if self.system_chk.get_active() \
            else Path.home() / ".local/share/wordperfect"

    def _on_version_changed(self, *_):
        # keep the target dir versioned (side-by-side 8.0 / 8.1)
        idx = self.version_dd.get_selected()
        if 0 <= idx < len(self._candidates):
            v = self._candidates[idx].version
            self.target_entry.set_text(str(self._version_base() / v))

    def _start_install(self, _btn):
        target = Path(self.target_entry.get_text().strip())
        if not self._candidates:
            self.opt_status.set_text("⚠  Press “Detect versions” and choose a version first.")
            return
        idx = self.version_dd.get_selected()
        if idx < 0 or idx >= len(self._candidates):
            self.opt_status.set_text("⚠  Choose a version to install.")
            return
        chosen = self._candidates[idx]
        # Don't silently overwrite an existing tree — ask first (the CLI would
        # refuse without --overwrite; the GUI turns that into a question).
        if target.exists() and target.is_dir() and any(target.iterdir()):
            dlg = Gtk.AlertDialog()
            dlg.set_message(f"An install already exists at {target}")
            dlg.set_detail("Installing over it replaces files with the same names "
                           "in place — there is no backup. Your ~/.wprc profile and "
                           "documents are not touched.\n\nOverwrite it, or cancel and "
                           "pick a different location?")
            dlg.set_buttons(["Cancel", "Overwrite"])
            dlg.set_cancel_button(0); dlg.set_default_button(0)
            dlg.choose(self.win, None, self._on_overwrite_confirm, chosen)
            return
        self._launch_install(chosen, target, overwrite=False)

    def _on_overwrite_confirm(self, dlg, res, chosen):
        try:
            idx = dlg.choose_finish(res)
        except Exception:  # noqa - dismissed
            return
        if idx != 1:                       # Cancel / dismissed -> stay on options
            return
        target = Path(self.target_entry.get_text().strip())
        self._launch_install(chosen, target, overwrite=True)

    def _launch_install(self, chosen, target, overwrite):
        self.stack.set_visible_child_name("progress")
        make_desktop = self.launcher_chk.get_active() and self.desktop_chk.get_active()
        threading.Thread(target=self._worker,
                         args=(chosen, target, self.system_chk.get_active(),
                               self.launcher_chk.get_active(), make_desktop, overwrite),
                         daemon=True).start()

    def _worker(self, chosen, target, system, make_launcher, make_desktop, overwrite=False):
        ok = True; stats = {}
        if system:
            # System-wide: elevate the WHOLE install with pkexec (desktop-standard
            # polkit prompt). As root it installs the tree to /opt AND a system
            # launcher in /usr/local/bin + menu entry in /usr/share/applications;
            # each user's ~/.wprc self-seeds at first run (no per-user step).
            GLib.idle_add(self._on_step,
                          Step("elevate", "Requesting admin access (pkexec)...", 0.02, ok=True))
            engine_py = str(Path(__file__).with_name("wp8_install.py"))
            # the elevated CLI does its own discovery/resolution of this exact path
            cmd = ["pkexec", sys.executable, engine_py, "--media", str(chosen.path),
                   "--target", str(target)]
            if overwrite:
                cmd.append("--overwrite")
            if not make_launcher:
                cmd.append("--no-launcher")
            if not make_desktop:
                cmd.append("--no-desktop")
            try:
                p = subprocess.run(cmd, capture_output=True, text=True)
            except Exception as e:  # noqa
                GLib.idle_add(self._on_step, Step("elevate", "pkexec failed", 0.1, ok=False, detail=str(e)))
                GLib.idle_add(self._on_finish, False, {}, target); return
            log = [l.strip() for l in p.stdout.splitlines() if l.strip()]
            ok = (p.returncode == 0)
            GLib.idle_add(self._on_step, Step(
                "system", "System-wide install (elevated)" if ok else "System install failed",
                1.0, ok=ok, detail="" if ok else (p.stderr or "cancelled/denied").strip()[:300],
                log=log[-16:]))
            GLib.idle_add(self._on_finish, ok, {"install": str(target)}, target)
            return
        else:
            try:
                with mediamod.resolve(chosen.path) as rm:
                    kind = "deb" if rm.kind == mediamod.DEB else "native"
                    eng = Engine(rm.root, target, make_launcher=make_launcher,
                                 make_desktop=make_desktop,
                                 version=rm.version, source_kind=kind,
                                 overwrite=overwrite)
                    for step in eng.run():
                        GLib.idle_add(self._on_step, step)
                        stats = eng.stats
                        if not step.ok:
                            ok = False; break
            except mediamod.MediaError as e:
                GLib.idle_add(self._on_step, Step("media", "Could not read media", 0.05,
                                                  ok=False, detail=str(e)))
                ok = False
        GLib.idle_add(self._on_finish, ok, stats, target)

    def _on_step(self, step):
        self.bar.set_fraction(step.fraction)
        self.bar.set_text(f"{int(step.fraction*100)}%  –  {step.title}")
        row = Gtk.Box(spacing=8); row.add_css_class("steprow")
        icon = Gtk.Label(label="✓" if step.ok else "✗")
        icon.add_css_class("ok" if step.ok else "fail")
        lab = Gtk.Label(label=step.title, xalign=0, hexpand=True)
        row.append(icon); row.append(lab)
        self.steps_box.append(row)
        for l in step.log:
            sub = Gtk.Label(label=f"     {l}", xalign=0); sub.add_css_class("subtitle")
            self.steps_box.append(sub)
        if not step.ok and step.detail:
            d = Gtk.Label(label=f"     {step.detail}", xalign=0, wrap=True); d.add_css_class("fail")
            self.steps_box.append(d)
        return False

    def _on_finish(self, ok, stats, target):
        self._target = target
        uninstalled = "uninstalled" in stats
        if uninstalled:
            self.done_title.set_text("Uninstalled" if ok else "Uninstall failed")
            (self.done_title.remove_css_class if ok else self.done_title.add_css_class)("fail")
            self.done_body.set_text(
                f"WordPerfect 8 was removed from {target}.\nYour ~/.wprc profile and "
                "documents were kept." if ok else "See the steps above for the error.")
            self.launch_btn.set_visible(False)
        elif ok:
            self.done_title.set_text("Installation complete")
            self.done_title.remove_css_class("fail")
            sysp = self._is_system_path(target)
            self._launch_path = "/usr/local/bin/xwp" if sysp else str(Path.home() / ".local/bin/xwp")
            summary = (f"{stats.get('decompressed',0)} files decompressed, "
                       f"{stats.get('drivers',0)} printer drivers, "
                       f"{stats.get('fonts',0)} fonts.\n\n"
                       f"Launch with  {self._launch_path}  (add -fontSize 20 for bigger menus).\n"
                       f"File locking works via the shim — no need to disable it.")
            self.done_body.set_text(summary)
            self.done_log.set_text("\n".join(f"{k}: {v}" for k, v in stats.items()))
            self.launch_btn.set_visible(True); self.launch_btn.set_sensitive(True)
        else:
            self.done_title.set_text("Installation failed")
            self.done_title.add_css_class("fail")
            self.done_body.set_text("See the steps above for the error.")
            self.launch_btn.set_visible(False)
        self.stack.set_visible_child_name("done")
        return False

    def _launch(self, _btn):
        launcher = getattr(self, "_launch_path", str(Path.home() / ".local/bin/xwp"))
        try:
            subprocess.Popen([launcher])
        except Exception as e:  # noqa
            self.done_body.set_text(f"Could not launch: {e}")


if __name__ == "__main__":
    um = "--uninstall" in sys.argv
    argv = [a for a in sys.argv if a != "--uninstall"]   # GApplication rejects unknown opts
    Installer(uninstall_mode=um).run(argv)
