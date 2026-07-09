/* wpdest.h — map WordPerfect print parameters to a CUPS lp/lpr command.
 * SPDX-License-Identifier: MIT
 *
 * WP tells the print helper a device (printer), a form/paper, orientation and
 * copies (from the .prs capabilities: letter/legal/a4/a3/envelope, Portrait/
 * Landscape). This turns that into a modern `lp -d P -o media=... -o
 * orientation-requested=... -n N` invocation. The body (PostScript) is fed on
 * stdin, so no filename is needed.
 */
#ifndef WPDEST_H
#define WPDEST_H
#include <stddef.h>

/* WP print settings that have a modern CUPS analog. (WP's obsolete ones —
 * /etc/printcap, wpp filters, WPREMOTE/WPOTHER ports — are intentionally not
 * modelled; CUPS subsumes them.) */
enum { WP_Q_AUTO = 0, WP_Q_DRAFT, WP_Q_NORMAL, WP_Q_HIGH };   /* Print Quality  */
enum { WP_C_AUTO = 0, WP_C_COLOR, WP_C_MONO };                /* Color / B&W    */

typedef struct {
    const char *device;      /* WP printer/device name; NULL => CUPS default    */
    const char *form;        /* friendly form ("letter"/"a4"/...) -> -o media=  */
    const char *page_size;   /* raw CUPS PageSize (e.g. "Env10"); wins over form */
    const char *source;      /* CUPS InputSlot / tray (e.g. "Tray2","Manual")   */
    const char *media_type;  /* CUPS MediaType (e.g. "card","envelope")         */
    const char *resolution;  /* CUPS Resolution (e.g. "1200x1200dpi")           */
    int         landscape;   /* 0 portrait, 1 landscape                          */
    int         duplex;      /* 0 off, 1 long-edge, 2 short-edge                 */
    int         copies;      /* <=0 => 1                                         */
    int         quality;     /* WP_Q_*  -> -o print-quality=                     */
    int         color;       /* WP_C_*  -> -o print-color-mode=                  */
    const char *pages;       /* "1-5,8"  -> -o page-ranges= ; NULL => all        */
} wp_dest;

/* Build the spool command line into `out` (size n). Returns out. The command
 * reads the job body from stdin (CUPS `lp`/`lpr` do by default). */
char *wp_dest_command(const wp_dest *d, char *out, size_t n);

/* Map a WP form name to a CUPS `media` value (e.g. "a4" -> "A4"). Returns NULL
 * if unknown (caller omits the -o media option, letting CUPS default). */
const char *wp_dest_media(const char *form);

#endif /* WPDEST_H */
