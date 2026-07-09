/* wpcups.h — enumerate the system's CUPS print destinations.
 * SPDX-License-Identifier: MIT
 *
 * The "select/add printer" flow lists CUPS queues (not WP .all drivers) and lets
 * the user pick which one WP's single Passthru-PostScript printer targets via
 * `lp -d <name>`. We shell out to `lpstat` (no libcups build dep) through the
 * wpexec runner.
 */
#ifndef WPCUPS_H
#define WPCUPS_H

#define WP_CUPS_NAMEMAX 128

/* Fill names[0..max-1] with CUPS destination names; return the count (<=max),
 * or -1 if lpstat is unavailable. */
int wp_cups_printers(char names[][WP_CUPS_NAMEMAX], int max);

/* Copy the system default destination into out (size n); return 0 on success,
 * -1 if none / lpstat missing. */
int wp_cups_default(char *out, int n);

/* Query one of a printer's PPD options (the modern analog of the WP .prs
 * capability tables). keyword is a CUPS option name: "PageSize", "InputSlot"
 * (tray/sheet feeder), "MediaType", "Resolution", "Duplex", "ColorModel".
 * Fills choices[0..max-1] with the allowed values, sets *def to the index of
 * the printer's default (the '*'-marked one, or -1), and returns the count
 * (<=max), or -1 if lpoptions/the printer is unavailable. */
int wp_cups_option(const char *printer, const char *keyword,
                   char choices[][WP_CUPS_NAMEMAX], int max, int *def);

#endif /* WPCUPS_H */
