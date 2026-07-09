/* wpdest.c — WordPerfect print params -> CUPS lp command. See wpdest.h.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "wpdest.h"

/* WP form/paper names (from the .prs capability strings) -> CUPS media keywords.
 * CUPS accepts these friendly names and maps them to PWG media sizes. */
static const struct { const char *wp; const char *cups; } MEDIA[] = {
    { "letter",   "Letter"   },
    { "legal",    "Legal"    },
    { "a4",       "A4"       },
    { "a3",       "A3"       },
    { "a5",       "A5"       },
    { "envelope", "Env10"    },   /* WP's default #10 envelope                   */
    { "tabloid",  "Tabloid"  },
    { "executive","Executive"},
};

const char *wp_dest_media(const char *form) {
    if (!form) return NULL;
    for (size_t i = 0; i < sizeof MEDIA / sizeof *MEDIA; i++)
        if (!strcasecmp(form, MEDIA[i].wp)) return MEDIA[i].cups;
    return NULL;   /* unknown -> let CUPS use the printer default */
}

/* Quote a token for /bin/sh (popen runs the command via sh -c). Simple, safe
 * single-quote wrapping; embedded quotes become '\''. */
static void shq(char *out, size_t n, const char *s) {
    size_t o = 0;
    if (o < n) out[o++] = '\'';
    for (; *s && o + 4 < n; s++) {
        if (*s == '\'') { memcpy(out + o, "'\\''", 4); o += 4; }
        else out[o++] = *s;
    }
    if (o < n) out[o++] = '\'';
    if (o < n) out[o] = 0; else if (n) out[n-1] = 0;
}

char *wp_dest_command(const wp_dest *d, char *out, size_t n) {
    /* Prefer `lp` (richer -o options); it reads stdin when given no file. */
    size_t o = (size_t)snprintf(out, n, "lp");
    char q[256];

    if (d->device && *d->device) {
        shq(q, sizeof q, d->device);
        o += (size_t)snprintf(out + o, o < n ? n - o : 0, " -d %s", q);
    }
    /* paper size: a raw CUPS PageSize (from the printer's PPD) wins over the
     * friendly form name. */
    const char *media = (d->page_size && *d->page_size) ? d->page_size
                                                        : wp_dest_media(d->form);
    if (media)
        o += (size_t)snprintf(out + o, o < n ? n - o : 0, " -o media=%s", media);
    if (d->source && *d->source)        /* tray / sheet feeder */
        o += (size_t)snprintf(out+o, o<n?n-o:0, " -o InputSlot=%s", d->source);
    if (d->media_type && *d->media_type)
        o += (size_t)snprintf(out+o, o<n?n-o:0, " -o MediaType=%s", d->media_type);
    if (d->resolution && *d->resolution)
        o += (size_t)snprintf(out+o, o<n?n-o:0, " -o Resolution=%s", d->resolution);
    if (d->duplex == 1) o += (size_t)snprintf(out+o, o<n?n-o:0, " -o sides=two-sided-long-edge");
    else if (d->duplex == 2) o += (size_t)snprintf(out+o, o<n?n-o:0, " -o sides=two-sided-short-edge");
    if (d->landscape)
        o += (size_t)snprintf(out + o, o < n ? n - o : 0, " -o orientation-requested=4");
    if (d->copies > 1)
        o += (size_t)snprintf(out + o, o < n ? n - o : 0, " -n %d", d->copies);
    /* Print Quality -> CUPS print-quality (3=draft,4=normal,5=high) */
    if (d->quality == WP_Q_DRAFT)  o += (size_t)snprintf(out+o, o<n?n-o:0, " -o print-quality=3");
    else if (d->quality == WP_Q_NORMAL) o += (size_t)snprintf(out+o, o<n?n-o:0, " -o print-quality=4");
    else if (d->quality == WP_Q_HIGH)   o += (size_t)snprintf(out+o, o<n?n-o:0, " -o print-quality=5");
    /* Color / Graphics in Black & White -> print-color-mode */
    if (d->color == WP_C_COLOR) o += (size_t)snprintf(out+o, o<n?n-o:0, " -o print-color-mode=color");
    else if (d->color == WP_C_MONO) o += (size_t)snprintf(out+o, o<n?n-o:0, " -o print-color-mode=monochrome");
    if (d->pages && *d->pages) {
        char q[128]; shq(q, sizeof q, d->pages);
        o += (size_t)snprintf(out+o, o<n?n-o:0, " -o page-ranges=%s", q);
    }
    return out;
}
