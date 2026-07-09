/* wpselect.c — choose which CUPS printer WP's Passthru-PostScript targets.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * This is the LOGIC behind the "select/add printer" flow. WordPerfect keeps its
 * one PostScript .prs; here we pick a CUPS *destination* for it. The choice is
 * written to a sidecar the sink reads ($WPCOM/wpsink.dest or --config), so no
 * per-printer .prs is minted. A GTK dialog will later wrap this exact logic, and
 * signal xwp over IPC that the current printer changed (<< CONFIRM (trace) >>:
 * the selection-side IPC message — likely e_device — from capture).
 *
 *   wpselect --list                 # show CUPS printers + default
 *   wpselect --set NAME [--config F]# record NAME as WP's print destination
 *   wpselect --get [--config F]     # print the current destination
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wpcups.h"

/* Print a printer's current CUPS defaults (read-only; configuration itself is
 * CUPS's job — system-config-printer / GNOME Settings / the CUPS web admin). */
static int do_info(const char *name) {
    static const char *keys[] = { "PageSize", "InputSlot", "MediaType" };
    static const char *labels[] = { "paper", "tray", "type" };
    char ch[64][WP_CUPS_NAMEMAX]; int def, printed = 0;
    for (int k = 0; k < 3; k++) {
        int n = wp_cups_option(name, keys[k], ch, 64, &def);
        if (n > 0 && def >= 0)
            printf("%s%s=%s", printed++ ? " " : "", labels[k], ch[def]);
    }
    printf("\n");
    return 0;
}

static const char *cfg_path(const char *o) {
    if (o) return o;
    static char p[256];
    const char *d = getenv("WPCOM"); if (!d || !*d) d = "/tmp";
    snprintf(p, sizeof p, "%s/wpsink.dest", d);
    return p;
}

static int do_list(void) {
    char names[64][WP_CUPS_NAMEMAX];
    int n = wp_cups_printers(names, 64);
    if (n < 0) { fprintf(stderr, "lpstat not available (install a CUPS client)\n"); return 1; }
    char def[WP_CUPS_NAMEMAX]; int haved = (wp_cups_default(def, sizeof def) == 0);
    if (n == 0) { printf("No CUPS printers configured. Add one in the CUPS admin, then re-run.\n"); return 0; }
    printf("CUPS printers (%d):\n", n);
    for (int i = 0; i < n; i++)
        printf("  %s%s\n", names[i], (haved && !strcmp(names[i], def)) ? "   [default]" : "");
    return 0;
}

int main(int argc, char **argv) {
    const char *set = NULL, *cfg = NULL; int get = 0, list = 0;
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i], "--list")) list = 1;
        else if (!strcmp(argv[i], "--set") && i+1 < argc) set = argv[++i];
        else if (!strcmp(argv[i], "--get")) get = 1;
        else if (!strcmp(argv[i], "--info") && i+1 < argc) return do_info(argv[++i]);
        else if (!strcmp(argv[i], "--config") && i+1 < argc) cfg = argv[++i];
        else { fprintf(stderr, "usage: %s --list | --set NAME | --get | --info NAME [--config F]\n", argv[0]); return 2; }
    }
    if (list) return do_list();
    if (set) {
        FILE *f = fopen(cfg_path(cfg), "w");
        if (!f) { perror("open config"); return 1; }
        fprintf(f, "%s\n", set); fclose(f);
        printf("WP print destination set to '%s' (%s).\n", set, cfg_path(cfg));
        printf("The sink will spool with: lp -d %s\n", set);
        return 0;
    }
    if (get) {
        FILE *f = fopen(cfg_path(cfg), "r");
        char line[WP_CUPS_NAMEMAX] = "";
        if (f && fgets(line, sizeof line, f)) { line[strcspn(line, "\n")] = 0; printf("%s\n", line); }
        else printf("(no destination set — CUPS default is used)\n");
        if (f) fclose(f);
        return 0;
    }
    fprintf(stderr, "usage: %s --list | --set NAME | --get [--config F]\n", argv[0]);
    return 2;
}
