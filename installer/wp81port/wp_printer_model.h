/* wp_printer_model.h — WordPerfect 8 (Linux) PRINTER-CAPABILITY subsystem, reverse-engineered.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * The printer analog of the font-resource RE (see installer/wp81port/FONT-RENDERING-MAP.md §19,
 * and the font structs in that file's §11/§14). This header captures, as compilable C structs with
 * EXACT byte offsets, the two things a CUPS backend must understand:
 *
 *   (1) the on-disk .prs printer-resource container (a WPC-magic resource file), and
 *   (2) the in-memory 0x374-byte "current printer" capability record WP builds from it.
 *
 * PROVENANCE / METHOD. Static analysis only (objdump -d -M intel, readelf, xxd, strings) of the two
 * shipped `xwp` binaries plus the on-disk .prs set. Where a field is confirmed by a specific
 * instruction, the disasm site is cited (`@0x...`). Where meaning is inferred or unwalked, the field
 * is named `unk_NN` / `pad` and marked "(inferred)" or "(UNCONFIRMED — needs live gdb on :144)".
 *
 * BINARIES / SECTIONS:
 *   8.0 xwp  ~/.local/share/wordperfect/8.0/wpbin/xwp   .text@0x08051370 .data@0x0873f220 .bss@0x087d8b50
 *   8.1 xwp  ~/.local/share/wordperfect/8.1/wpbin/xwp   .text@0x0804b210 .data@0x0875b430 .bss@0x087f9860
 *   .rodata/.data file-offset -> VA: 8.0 uses the deltas in FONT-RENDERING-MAP §15/§18.
 *
 * KEY CROSS-VERSION RESULT: the 0x374-byte printer record layout is BYTE-IDENTICAL between 8.0 and
 * 8.1 — every field below sits at the same +offset in both, and every 8.1 field global carries the
 * same reference count as its 8.0 twin (verified field-by-field). So one struct serves both builds.
 */
#ifndef WP_PRINTER_MODEL_H
#define WP_PRINTER_MODEL_H
#include <stdint.h>

/* ========================================================================================= *
 * PART 1 — THE .prs ON-DISK FORMAT (WPC resource container)
 * ========================================================================================= *
 *
 * A .prs is a standard WordPerfect "WPC" resource file: the 16-byte WPC prefix, then a packet-
 * pointer index, then the driver body (driver name, page-size/"form" table, printer-font table,
 * kerning-pair tables, and the device command strings — PCL escapes for a PCL driver, or the
 * PostScript prolog for a PostScript driver).
 *
 * TWO .prs FAMILIES SHIP (correction to FONT-RENDERING-MAP §15.4, which called default.prs
 * "passthru PostScript" — they are byte-identical to each other, but the CONTENT is PCL):
 *   - ~85 KB  HP LaserJet III  *PCL*  : shlib10/default.prs == shlib10/passpost.prs (both 85875 B,
 *             cmp-clean), ~/.wprc/hp3d.prs (86054 B). Strings: "HP LaserJet III", PCL escapes
 *             ("*p+13x-13Y", "*c3a27bP"), and "The HP LaserJet III does not support automatic
 *             duplexing." => the duplex capability is encoded as PROSE/flags in the driver here.
 *   - ~24 KB  Passthru PostScript      : shlib10/pssave.prs (24283 B), ~/.wprc/passpost.prs
 *             (24285 B). Strings: "Passthru PostScript", "Apple LaserWriter", Type1 face names.
 *             THIS is the family that emits %!PS-Adobe (live-verified, §18.8). Header is
 *             structurally identical to the PCL family (same 16-byte prefix + index shape).
 */

/* The fixed 16-byte WPC file prefix. CONFIRMED by xxd of default.prs / passpost.prs / pssave.prs —
 * identical across all three: `ff 57 50 43 12 00 00 00 01 10 05 01 00 00 12 00`. */
typedef struct wp_prs_header {              /* 8.0 & 8.1 on-disk; offset 0 of every .prs */
    uint8_t  magic[4];      /* +0x00  0xFF 'W' 'P' 'C'                                  CONFIRMED */
    uint32_t data_ptr;      /* +0x04  file off of doc/data area (LE); = 0x12 in all .prs seen     */
    uint8_t  product;       /* +0x08  product id; 0x01 = WordPerfect                    CONFIRMED */
    uint8_t  file_type;     /* +0x09  file type; 0x10 for .prs printer resource         CONFIRMED */
    uint8_t  major;         /* +0x0a  format major; 0x05                                CONFIRMED */
    uint8_t  minor;         /* +0x0b  format minor; 0x01                                CONFIRMED */
    uint16_t crypt_key;     /* +0x0c  encryption key; 0x0000 = not encrypted           CONFIRMED */
    uint16_t index_ptr;     /* +0x0e  = 0x0012; start of the packet index just below   (inferred) */
} wp_prs_header;            /* sizeof 0x10 */

/* The packet index (starts ~file off 0x10). It is a table of 32-bit FILE OFFSETS to the capability
 * packets. EVIDENCE the entries are file-offset pointers: the little-endian dword 0x0000118e
 * appears in the index and 0x118e is exactly the start of the on-disk page-size name list
 * ("Letter (Portrait)"@0x10ab ... runs to ~0x118e); the dword 0x000069ce points into the
 * printer-font region ("roman8"@0x69c1, "CG Times"@0x6a82). 0xffffffff entries = "packet absent".
 * The EXACT per-entry record layout (tag/size/offset field widths and count) was NOT fully walked
 * statically. Treat this struct as the confirmed SHAPE (a pointer table) with an unconfirmed stride. */
typedef struct wp_prs_index_entry {         /* (UNCONFIRMED per-entry widths — needs loader disasm) */
    uint16_t tag;           /* +0x00  packet tag/id (inferred)                                      */
    uint16_t size_or_flags; /* +0x02  size or flags (inferred)                                      */
    uint32_t file_off;      /* +0x04  file offset of the packet, or 0xffffffff if absent  (inferred)*/
} wp_prs_index_entry;

/* Capability packets the index points at (contents CONFIRMED by `strings -t x`; struct is a
 * DESCRIPTIVE map of what each packet holds, not a byte-exact layout of the packet interior):
 *
 *   PAGE-SIZE / "FORM" packet   (default.prs @~0x10ab): a list of named page sizes, e.g.
 *       "Letter (Portrait)", "Letter (Landscape)", "A4 (Portrait)", "A4 (Landscape)",
 *       "Legal (Portrait/Landscape)", "Envelope (COM 10)/(C5)/(DL)/(Monarch)",
 *       "Executive (Portrait/Landscape)", "Carta (Portrait/Landscape)", "[ALL OTHERS]".
 *       These are surfaced to the UI as `Available_Paper_Definitions_s` (see PART 3).
 *   PRINTER-FONT packet          (default.prs @~0x69ce / @~0x10785): the printer's SUPPORTED-FONT
 *       list — face names + descriptors: "CG Times", "CG Times Bold/Italic/Bold Italic",
 *       "Univers" (+ variants), "Courier", "Line Printer"; plus tf_* internal tokens
 *       ("tf_arial", "tf_symbol", "tf_dingbats", ...). This is the list §17/§19.5 must widen so
 *       print-time substitution dies (present ALL our TTFs as supported).
 *   KERNING packets              (default.prs @~0x10808+): large ASCII kern-pair tables.
 *   DEVICE-COMMAND packet        (PCL family: raw PCL escapes; PS family: the %!PS prolog + Type1
 *       font programs). This is what ends up in the spooled job body.
 */

/* ========================================================================================= *
 * PART 2 — THE IN-MEMORY CURRENT-PRINTER / CAPABILITY RECORD  (THE struct the CUPS backend feeds)
 * ========================================================================================= *
 *
 * A single 0x374-byte (884-byte) record in .bss, one per process, holding the CURRENTLY SELECTED
 * printer's identity + active scalar capability selections. It is NOT where the enumerable
 * capability TABLES live (those stay in the .prs resource, enumerated on demand — see PART 3).
 *
 *   8.0 base 0x088125bc   8.1 base 0x08832b3c
 *   pointer global holding &record: 8.0 0x0878e6a0 / 8.1 0x087aa8bc
 *     (writer 8.0 0x081c7190: `movl $0x88125bc,0x878e6a0` @0x81c719e; 8.1 @0x81a7ada)
 *
 * The record is (re)initialized by a `rep movsl` of exactly 0xdd (221) dwords = 0x374 bytes:
 *   - init-from-template (fallback default): 8.0 fn 0x08124ef0 — `mov edi,0x88125bc; mov
 *     esi,0x87ad4d8; mov ecx,0xdd; rep movsd` @0x8124f0e, guarded by name[0]==0 && !(flags&0x40).
 *     0x087ad4d8 is a paired 0x374-byte template global that travels WITH the record (both are
 *     save/restored together in the capability-context swap helper 8.0 0x08237fd0, which installs
 *     an alternate record 0x087994e8 to query a resource by code, then restores).
 *   - copy-out to a stack scratch (for a query): 8.0 @0x81226c4 (`mov esi,0x88125bc; ecx=0xdd`).
 *
 * OFFSETS BELOW: name @+0x4c is CONFIRMED (26 refs 8.0 / 15+ 8.1; §15.2). Resolution @+0x1ec is
 * CONFIRMED (default 0x258=600 dpi; consumed by the font-metric loader). Others are labelled by
 * their read/write context; unwalked spans are `unk`/`pad`. The record interior is dense — many of
 * the 884 bytes are copied verbatim from the .prs and never individually referenced by xwp, so the
 * gaps here are real "we did not need to name it" gaps, not oversights.
 */
typedef struct wp_printer_record {  /* 8.0 @ 0x088125bc, 8.1 @ 0x08832b3c ; sizeof 0x374 (884) */

    uint8_t  unk_00[0x4c];      /* +0x000  driver header copied from .prs; not individually walked.
                                 *          (first dword has 31 refs as the record base itself.)   */

    char     name[0x4c];        /* +0x04c  DISPLAY NAME, NUL-terminated. Empty 1st byte =
                                 *          "NO PRINTER SELECTED". 8.0 0x8812608 / 8.1 0x8832b88.
                                 *          CONFIRMED @0x8124efc `cmpb $0,0x8812608`; §15.2. Size is
                                 *          the span to the next named field (+0x98). (inferred len) */

    char     name2[0x1a];       /* +0x098  secondary name string (driver/base name). 8.0 0x8812654.
                                 *          Used with name3 to compose the full label: at
                                 *          0x8164346 `push 0x8812654; push 0x881266e; call ...`;
                                 *          also strcpy'd @0x8124f4e. (len inferred to next field)   */

    char     name3[0xa0];       /* +0x0b2  tertiary string (port / device LOCATION, e.g. the
                                 *          "at CLX-3160" tail). 8.0 0x881266e. Checked empty
                                 *          @0x8124f34 `cmpb $0,0x881266e` before compose.
                                 *          (len inferred to next named field +0x152)               */

    char     font_desc1[0x4c];  /* +0x152  printer-font descriptor name, part 1 (face/family).
                                 *          8.0 0x881270e. Read by the font-metric consumer
                                 *          (0x85b4240): `push 0x881270e` @0x85b42ae; also composed
                                 *          in the setter (0x8163df0) @0x8164248. Feeds the
                                 *          resolution-keyed metric loader. (len inferred)  CONFIRMED
                                 *          as a font-name string; exact length UNCONFIRMED.        */

    char     font_desc2[0x4e];  /* +0x19e  printer-font descriptor name, part 2 (subfamily/variant).
                                 *          8.0 0x881275a. Appended to font_desc1 after a separator
                                 *          when non-empty: @0x85b42d4 `cmpb $0,0x881275a; je`, then
                                 *          strcat @0x85b42ea. (len inferred)                        */

    uint16_t resolution_dpi;    /* +0x1ec  ACTIVE RESOLUTION in DPI. 8.0 0x88127a8 / 8.1 0x8832d28.
                                 *          Default 0x258 = 600: set @0x8125166 `movl $0x258,...`;
                                 *          8.1 @0x810f6c4. Consumed by the metric loader: if !=0 use
                                 *          it else fall back to 0x258 (@0x85b4310..0x85b4341 ->
                                 *          call 0x8531300; 8.1 @0x8534c4c). Written by the setter
                                 *          @0x8164272 (8.1 @0x814a585). ★ CONFIRMED.
                                 *          NB: stored/read as a WORD here, but the setter writes a
                                 *          DWORD to this addr, so +0x1ee is effectively reserved.   */

    uint16_t unk_1ee;           /* +0x1ee  high half of the dword the setter writes at +0x1ec; the
                                 *          consumer only reads the low word. (inferred: reserved)   */

    uint8_t  font_type;         /* +0x1f0  printer-font TYPE nibble. 8.0 0x88127ac / 8.1 0x8832d2c.
                                 *          Consumer masks low nibble & compares ==6 to pick the
                                 *          scalable-font metric path: @0x85b428e `mov al,0x88127ac;
                                 *          and al,0xf; cmp al,6`. Written by the setter @0x816427d
                                 *          (8.1 @0x814a590). CONFIRMED as a type discriminator.     */

    uint8_t  unk_1f1;           /* +0x1f1  (inferred) padding / adjacent to font_type & flags.      */

    uint8_t  flags;             /* +0x1f2  ATTR/STATUS flag byte. 8.0 0x88127ae / 8.1 (loaded-flag
                                 *          0x87aa8b8, see §15.2). bit 0x40 = "use template default"
                                 *          gate (set @0x81c7197 `movb $0x40,0x88127ae`); bit 0x08 =
                                 *          a status/ready bit gating a status-bar control
                                 *          (@0x81d98d7 `test $0x8,0x88127ae`). CONFIRMED byte;
                                 *          individual bit meanings partly inferred.                 */

    uint8_t  unk_1f3[0x5];      /* +0x1f3  (inferred) not individually referenced.                  */

    uint8_t  port_type;         /* +0x1f8  connection/output TYPE enum. 8.0 0x88127b4 / 8.1
                                 *          0x8832d34. Discrete values gate UI sensitivity in the
                                 *          status-bar updater: @0x81d9900 `add al,0xfb; cmp al,1;
                                 *          jbe` (i.e. value in {5,6}) else `cmp 0xa`/`cmp 0x7`.
                                 *          (inferred: port/output kind; exact enum UNCONFIRMED.)    */

    uint8_t  unk_1f9[0x30];     /* +0x1f9  (inferred) unwalked span.                                 */

    char     str_229[0x4c];     /* +0x229  a string buffer (form/paper-name scratch; pushed heavily
                                 *          near 0x80e31xx). 8.0 0x88127e5. (inferred; len inferred) */

    uint8_t  unk_275[0x5b];     /* +0x275  (inferred) unwalked span.                                 */

    uint8_t  unk_2d0[0xa4];     /* +0x2d0  (inferred) unwalked span; 0x88127.. references thin out
                                 *          past here. 0x881288c has a single push. Runs to 0x374.   */
} wp_printer_record;            /* +0x374 == end. NB the WORD at record+0x374 (8.0 0x8812930) is a
                                 * SEPARATE adjacent global (a list count: init 0 @0x80b939b,
                                 * `incw`/compares elsewhere), NOT part of this record. */

/* Compile-time offset asserts for the CONFIRMED fields (guards against edits drifting the layout). */
#if defined(__GNUC__) || defined(__clang__)
_Static_assert(__builtin_offsetof(wp_printer_record, name)           == 0x04c, "name @+0x4c");
_Static_assert(__builtin_offsetof(wp_printer_record, resolution_dpi) == 0x1ec, "res  @+0x1ec");
_Static_assert(__builtin_offsetof(wp_printer_record, font_type)      == 0x1f0, "type @+0x1f0");
_Static_assert(__builtin_offsetof(wp_printer_record, flags)          == 0x1f2, "flag @+0x1f2");
_Static_assert(__builtin_offsetof(wp_printer_record, port_type)      == 0x1f8, "port @+0x1f8");
_Static_assert(sizeof(wp_printer_record)                             == 0x374, "record 0x374");
#endif

/* ========================================================================================= *
 * PART 3 — WHERE THE ENUMERABLE CAPABILITY TABLES LIVE (the interception surface)
 * ========================================================================================= *
 *
 * The lists WP shows in Page Setup / Print / Select-Printer (paper sizes, resolutions, bins,
 * duplex, color) are NOT arrays in wp_printer_record. They come from two places, resolved ON DEMAND:
 *
 *   A) the .prs RESOURCE, opened via WP's resource primitives:
 *        open  8.0 0x08420140  (8.1 0x083c6d84)   -- also the font-builder's open primitive
 *        query-by-code 0x080bdaa0                 -- (e.g. codes 0xfa, 0x9252 seen in 0x08237fd0)
 *        close 8.0 0x08420160  (8.1 0x083c6d98)
 *      driver-DB resource handle 0x08812f90 / token 0x08812f8c (the printer-side resource, §14).
 *
 *   B) the SETTINGS / ENVIRONMENT DB, keyed by NAME-HASHED tokens (NOT by address — none of these
 *      strings is push'd directly in xwp; they are looked up through the settings DB accessor).
 *      Confirmed token strings present in xwp 8.0 .rodata:
 *        "Available_Paper_Definitions_s"  (0x086e062d)  -- the paper/page-size list
 *        "Paper_Size_s" (0x086e0664)  "Paper_Name_s"  "Paper_Location_s" (0x086e09ab)
 *        "Paper_Width_s" (0x086e021d)  "Paper_Height_s"  "Paper_Type_s"  "Legal_Paper_s"
 *        "Wide_Form_s"  "Prompt_to_Load_Paper_s"  "PaperSizeCreate/Edit/Delete_s"
 *        "Duplexing_s"  (0x086d86f0)                     -- the duplex flag
 *        "WSID_RC_COLOR" (0x086de791)                    -- color capability id
 *        (identity/route tokens, shared with wprint/wpexc: "Current_Printer_s",
 *         "Destination_s", "Spooler_s", "Printer_Driver_s", "Number_of_Copies_s".)
 *
 * So the CUPS backing model is: intercept (A) the .prs capability-table enumeration and/or (B) the
 * settings-DB token reads, and answer from P2CCaps (printertocups/p2c.h). See §19 for the mapping.
 */

/* ========================================================================================= *
 * PART 4 — THE PRINTER-ENUMERATION PER-ENTRY STRUCT  (repeated from §15.1 for a complete model)
 * ========================================================================================= *
 * The list of AVAILABLE printers (Select-Printer dialog) is a calloc'd array of these 0x9c-byte
 * entries, built by the DB-scan core (8.0 0x0852cb40 / 8.1 0x084bb0c4), per-entry copier
 * 8.0 0x0852cd50 / 8.1 0x084bb2d0. Rich array base/count: 8.0 0x08803140 / 0x08803144
 * (8.1 0x08822a38 / 0x08822a48). This is where CUPS destinations are injected (§15.1 / §19.1). */
typedef struct wp_printer_enum_entry {   /* 8.0 array @[0x08803140], 8.1 @[0x08822a38]; sizeof 0x9c */
    uint16_t record_id;      /* +0x00  driver-record id/token     (`mov %ax,(%esi)`)      CONFIRMED */
    char     name[0x20];     /* +0x02  DISPLAY NAME (memcpy $0x20 from driver rec +0x1a)  CONFIRMED */
    uint8_t  unk_22[0x10];   /* +0x22  (inferred) unwalked                                          */
    char     short_code[0x8];/* +0x32  short code (memcpy $0x8 from rec +0x58)            CONFIRMED */
    uint8_t  unk_3a[0x4];    /* +0x3a  (inferred)                                                   */
    char     desc2[0x1e];    /* +0x3e  secondary description (memcpy $0x1e from rec +0x3a) CONFIRMED*/
    uint8_t  unk_5c[0x10];   /* +0x5c  (inferred)                                                   */
    char     driver_file[0x20];/*+0x6c  driver FILE basename (.all/.prs ref; memcpy $0x20 from rec
                                 *        +0x60 @0x852cdaf). (UNCONFIRMED that this is specifically
                                 *        the .prs basename — it is the 2nd 0x20 name-like field;
                                 *        live check per §15.1.)                                     */
    uint8_t  unk_8c[0x10];   /* +0x8c  (inferred) tail to 0x9c                                      */
} wp_printer_enum_entry;     /* sizeof 0x9c (156) */

/* ========================================================================================= *
 * PART 5 — PAPER-SIZE / TYPE DEFINITIONS  ("FORMS")   [the media + media-source layer for CUPS]
 * ========================================================================================= *
 *
 * WP calls a paper-size/type definition a "FORM". Format > Page > Paper Size/Type edits the list;
 * each Form binds a NAME, a physical SIZE, an input SOURCE/tray, an ORIENTATION, and flags
 * (prompt-to-load, wide, text-adjust, ...). At print time WP resolves the selected Form to its
 * size+source and stamps them into the layout / PostScript (the PS body carries the form keyword,
 * e.g. `letter`, live-verified §18.8) and the job spec.
 *
 * (1) STORAGE — CONFIRMED: Forms live INSIDE the printer's .prs, as a dedicated packet (one of the
 *     wp_prs_index_entry targets). Every .prs carries its own Form list — even the daisywheel
 *     ~/.wprc/aegolyro.prs (AEG Olympia) has a Form packet, and it lists ONLY portrait sizes
 *     ([ALL OTHERS], Letter/Legal/A4/Carta Portrait) because that device cannot rotate — proof the
 *     list is per-printer .prs data, not a global table. The user's writable copy lives in ~/.wprc
 *     (WP copies shlib10/<drv>.prs there on install); the user's ~/.wprc/passpost.prs (24285 B)
 *     already differs from the template shlib10/pssave.prs (24283 B) in the driver-name + Form
 *     region — i.e. Add/Edit/Delete Form rewrites the .prs. The current-SELECTION (which Form is
 *     active, current printer name) persists separately in the settings DB (~/.wprc/.wpc8x.set,
 *     ~/.wprc/.wp8x.set) and the document, NOT the Form geometry.
 *
 * (2)+(3) The Form packet on disk = a run of fixed binary Form records, then a name block
 *     (count + u16 offset table + packed NUL-terminated names). CONFIRMED by hex-dump of
 *     aegolyro.prs @0x3a0 and default.prs @0x1040. Widths/heights are u16 in WP UNITS = 1200ths
 *     of an inch (same 1200 unit as the 8.1 device scaler, FONT-RENDERING-MAP §14): decoded values
 *     0x27d8=10200=8.5in, 0x3390=13200=11in (Letter), 0x41a0=16800=14in (Legal),
 *     0x26c1/0x36cf = 9921/14031 = A4 (210x297mm). The per-record byte layout below is the
 *     confirmed SHAPE; the exact stride and the meaning of the leading/trailing bytes are
 *     (inferred) — a live diff (create a Form on Xvfb :144, save to file, diff the .prs) or the
 *     loader disasm is needed to lock the stride and the source/orientation bytes exactly. */
typedef struct __attribute__((packed)) wp_prs_form_record {  /* .prs Form packet; aegolyro.prs @0x3a0, default.prs @0x1040 */
    uint16_t marker;        /* +0x00  0x0004 record marker/field-count (inferred)                  */
    uint16_t orient;        /* +0x02  orientation/type: 0x0003 for [ALL OTHERS], 0x0001 others.
                             *          (inferred: portrait/landscape/rotated discriminator)        */
    uint16_t flags;         /* +0x04  flags word: 0x0020 vs 0x0120 seen (bit 0x0100 = wide/rotated?
                             *          maps to Wide_Form_s / rotated-fill). (inferred)              */
    uint8_t  source_id;     /* +0x06  input SOURCE / tray id: 0xff=default/continuous, 0x01/0x04/
                             *          0x06 = specific bins. -> CUPS "media-source". (inferred id;
                             *          that it is the tray selector is inferred from position +
                             *          value pattern, confirm on live diff.)                        */
    uint16_t width_wpu;     /* +0x07  paper WIDTH  in 1200ths-inch (unaligned). 0x27d8=8.5in etc.
                             *          -> CUPS "media" width. ★ CONFIRMED (values decode exactly). */
    uint16_t height_wpu;    /* +0x09  paper HEIGHT in 1200ths-inch (unaligned). 0x3390=11in,
                             *          0x41a0=14in. -> CUPS "media" height. ★ CONFIRMED.            */
    uint8_t  tail;          /* +0x0b  0xb0 / 0x00 trailing byte (inferred; end-of-record or a flag) */
} wp_prs_form_record;       /* stride ~0x0c (UNCONFIRMED exact); records are NOT in name-table order */

/* The Form name block that follows the record run (CONFIRMED shape; aegolyro @~0x3d8,
 * default @~0x1082): a u16 count, a u16[count] table of offsets into the packed name area, then
 * the NUL-terminated names ("[ALL OTHERS]", "Letter (Portrait)", "Letter (Landscape)", ...).
 * default.prs count = 0x000d (13 forms); aegolyro = fewer (portrait only). The offset base and the
 * record<->name pairing index were not byte-exactly walked (inferred). */
typedef struct wp_prs_form_names {     /* variable length */
    uint16_t count;         /* +0x00  number of Form names (default.prs = 13)          CONFIRMED cnt */
    uint16_t name_off[1];   /* +0x02  u16[count] offsets into the packed name area (inferred base)  */
    /* char names[]; -- packed NUL-terminated Form names follow the offset table.                   */
} wp_prs_form_names;

/* (2) IN-MEMORY Form / Paper dialog. The Format>Page>Paper "Create/Edit" dialog's fields are the
 * Motif text widgets "FormNameTxt", "FormWidthTxt", "FormLengthTxt" (+ "FormatCombo"/"FormatCombo2"
 * for type/source), and the list title "PaperSizeTitle"; the query tokens are "PAPERWIDTH_QRY_p",
 * "PAPERLENGTH_QRY_p", "PAPERSZTYPE_QRY_p"/"PAPERSZTYPE_TKN_p". So the in-memory edit struct maps
 * 1:1 to the on-disk Form record: name<-FormNameTxt, width_wpu<-FormWidthTxt, height_wpu<-
 * FormLengthTxt, source/orient<-FormatCombo. The dialog is surfaced through the settings-DB tokens
 * "Available_Paper_Definitions_s" (the list), "Paper_Size_s"/"Paper_Name_s"/"Paper_Location_s"/
 * "Paper_Width_s"/"Paper_Height_s"/"Paper_Type_s", "PaperSizeCreate/Edit/Delete_s",
 * "Delete_Paper_Def_s", "Legal_Paper_s", "Wide_Form_s", "Prompt_to_Load_Paper_s".
 *
 * (GAP) The Format>Page>Paper dialog builder + Add/Edit/Delete/Select FUNCTION ADDRESSES were NOT
 * located statically: those widget names and the QRY_p / _s tokens are all resolved through WP's
 * widget-id / settings-DB NAME-HASH tables (none is push'd by address in xwp), so there is no static
 * xref to follow. Needs a live gdb pass on Xvfb :144 (file-only): break on XmString/list-add during
 * the Paper dialog to catch the builder, and on the .prs writer to catch Add/Edit/Delete.
 *
 * (4) FEED TO JOB. At print (§18.8) the selected Form's size becomes the PostScript page keyword in
 * the job body (e.g. `letter`) emitted by wppx, and the size/orientation drive layout; the device
 * name + spool template go into the job spec /tmp/_wq<pid>_1. For CUPS: translate the active Form's
 * width_wpu/height_wpu (÷1200 = inches, ×25.4 = mm) into a P2COpt {"media", "<PWG size>"} and
 * source_id into {"media-source", "<tray>"} on p2c_submit (printertocups/p2c.h). Because the
 * passthru driver already emits correct PostScript for the chosen size, the CUPS media option is
 * belt-and-suspenders (CUPS honors the queue default) — but sending it makes tray selection work. */

#endif /* WP_PRINTER_MODEL_H */
