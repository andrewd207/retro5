/* tests.c — unit tests for the wpprint-sink components. cc -o t tests.c wpdest.c wpexec.c wpproto.c */
#include <stdio.h>
#include <string.h>
#include "wpdest.h"
#include "wpexec.h"

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void) {
    char buf[512];

    /* wpdest: media mapping */
    CHECK(!strcmp(wp_dest_media("a4"), "A4"));
    CHECK(!strcmp(wp_dest_media("Letter"), "Letter"));
    CHECK(!strcmp(wp_dest_media("envelope"), "Env10"));
    CHECK(wp_dest_media("banana") == NULL);

    /* wpdest: command building (designated inits — struct grows over time) */
    wp_dest d1 = { .device="HP_LaserJet", .form="a4", .landscape=1, .copies=2 };
    wp_dest_command(&d1, buf, sizeof buf);
    CHECK(!strcmp(buf, "lp -d 'HP_LaserJet' -o media=A4 -o orientation-requested=4 -n 2"));

    wp_dest d2 = { .form="letter" };
    wp_dest_command(&d2, buf, sizeof buf);
    CHECK(!strcmp(buf, "lp -o media=Letter"));

    wp_dest d3 = { .device="it's mine" };                   /* shell-quoting */
    wp_dest_command(&d3, buf, sizeof buf);
    CHECK(!strcmp(buf, "lp -d 'it'\\''s mine'"));

    /* quality, color, page range */
    wp_dest d4 = { .device="P", .quality=WP_Q_HIGH, .color=WP_C_MONO, .pages="1-3" };
    wp_dest_command(&d4, buf, sizeof buf);
    CHECK(!strcmp(buf, "lp -d 'P' -o print-quality=5 -o print-color-mode=monochrome -o page-ranges='1-3'"));

    /* paper size / tray / media type / resolution / duplex (from the PPD) */
    wp_dest d5 = { .device="CLX", .page_size="Env10", .source="Tray2",
                   .media_type="envelope", .resolution="1200x1200dpi", .duplex=1 };
    wp_dest_command(&d5, buf, sizeof buf);
    CHECK(!strcmp(buf, "lp -d 'CLX' -o media=Env10 -o InputSlot=Tray2 -o MediaType=envelope "
                       "-o Resolution=1200x1200dpi -o sides=two-sided-long-edge"));

    /* wpexec: run a command, capture stdout, feed stdin */
    char out[64]; size_t cap = sizeof out;
    char *const av[] = { "cat", NULL };
    int st = wp_run("cat", av, "hello", 5, out, &cap);
    CHECK(st == 0);
    CHECK(cap == 5 && !memcmp(out, "hello", 5));

    char *const af[] = { "false", NULL };
    cap = sizeof out;
    CHECK(wp_run("false", af, NULL, 0, out, &cap) == 1);

    printf(fails ? "TESTS FAILED (%d)\n" : "ALL TESTS PASS\n", fails);
    return fails ? 1 : 0;
}
