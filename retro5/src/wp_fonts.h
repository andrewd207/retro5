/* wp_fonts.h — WordPerfect 8.0 (Linux) internal font-engine structures & addresses.
 * SPDX-License-Identifier: MIT  ·  Copyright (c) 2026 Andrew Haines
 *
 * Reverse-engineered from the INSTALLED 8.0.0076 dynamic-X build
 *   ~/.local/share/wordperfect/8.0/wpbin/xwp   (.text @ 0x08051370)
 * by objdump disassembly + live gdb inspection of a throwaway :141 instance
 * (NOT the user's session). Cross-referenced with installer/wp81port/FONT-RENDERING-MAP.md
 * (which ports the symbol-bearing 8.1 ghidra_hl build). All addresses here are 8.0-native.
 *
 * Confidence: fields tagged "OK" (in their trailing comment) were read live and confirmed;
 * "?" marks structural guesses not yet proven. Offsets are byte offsets into the struct.
 *
 * These are the structures the retro5 shim reads when re-rendering the document canvas with
 * cairo (face matching), and — later — when injecting system fonts and supplanting metrics.
 */
#ifndef WP_FONTS_H
#define WP_FONTS_H
#include <stdint.h>

/* ======================================================================================
 * Global addresses (8.0 wpbin/xwp)
 * ==================================================================================== */

/* --- the enumerated font table (one entry per available typeface) --- */
#define WP_FONTREC_ARR   0x08808754u  /* uint32 -> wp_font_record*[]  (deref once for the base) */
#define WP_FONTREC_CAP   0x08808758u  /* uint16    capacity (records allocated)                 */
#define WP_FONTREC_CNT   0x0880875au  /* uint16    live count (enumerated fonts). Live: 127      */
#define WP_FONTREC_REMAP 0x0880876cu  /* uint32 -> uint16 remap[];  index = remap[0xfff - code]  */

/* --- the "currently selected font" trio (set by the context builder, 0x085b9a30) --- */
#define WP_CUR_GLYPHTAB  0x08808794u  /* uint32 -> wp_glyph_table*  (== context->glyph_table)    */
#define WP_CUR_METRIC    0x0880878cu  /* uint32 -> wp_font_metric*  (== glyph_table->metric,     */
                                      /*            == active record->rasterized)                */
#define WP_CUR_CONTEXT   0x08808798u  /* uint32 -> wp_font_context* (per-font display context)   */
#define WP_CUR_DISPCTX   0x08808790u  /* uint32 -> display ctx fed to the context builder      ? */
#define WP_METRICS_READY 0x0880879cu  /* uint8     "metrics loaded" flag                         */
#define WP_FALLBACK_CODE 0x087bdfe4u  /* uint32    fallback/default font code (0xfff0000 live)  ? */

/* --- the document-canvas pen / target (written by draw_text_run 0x085b54e0) --- */
#define WP_PEN_X         0x087bdd5cu  /* int32     glyph origin X, device px                     */
#define WP_PEN_Y         0x087bdd60u  /* int32     baseline Y,     device px                     */
#define WP_CANVAS_GC     0x087bdd8cu  /* GC        canvas graphics context                       */
#define WP_CANVAS_WIN    0x087bdd90u  /* Drawable  canvas window                                 */
#define WP_RES_DIVISOR   0x087a42e4u  /* int32     resolution/zoom denominator (WPU->px idiv)    */

/* ======================================================================================
 * Function addresses (8.0 wpbin/xwp)
 * ==================================================================================== */
#define WP_FN_DRAW_TEXT_RUN  0x085b54e0u /* void(char* buf,u16 count,i16 penx,i16 peny,i32,u8)   */
#define WP_FN_RESOLVE_FONT   0x085b7860u /* record* (u32 fontcode): remap->record, load+raster    */
#define WP_FN_LOAD_PFB       0x085b9400u /* load Type1 .pfb for a record (record+0x08 arg)         */
#define WP_FN_RASTERIZE      0x085ba9c0u /* rasterize outline at size                             */
#define WP_FN_WPU_TO_PX      0x085b3d20u /* WP-unit -> device px (÷ WP_RES_DIVISOR)               */
#define WP_FN_GET_GLYPHTAB   0x085b9840u /* wp_glyph_table* (void): returns [WP_CUR_GLYPHTAB]     */
#define WP_FN_GET_METRIC     0x085b9850u /* wp_font_metric* (void): returns [WP_CUR_METRIC]       */
#define WP_FN_LOAD_METRICS   0x085b9ea0u /* fill the metric struct (+0x5a0 width table)           */
#define WP_FN_BUILD_CONTEXT  0x085b9a30u /* build the per-font display context (sets the trio)    */

/* ======================================================================================
 * Structures
 * ==================================================================================== */

/* --- Font record: one per enumerated typeface. calloc(1, 0x20) = 32 bytes. --------------
 * Array of pointers to these at *(WP_FONTREC_ARR), WP_FONTREC_CNT live entries. The Font
 * dialog, the resolver, and the canvas all key off this single record type. */
typedef struct wp_font_record {
    uint16_t flags;          /* +0x00 OK  attribute word (bit 0x8000 tested by the name getter) */
    uint16_t _pad02;         /* +0x02  ?                                                        */
    uint32_t src_a;          /* +0x04  ?  source ptr/id copied from the build source struct     */
    uint32_t src_b;          /* +0x08 OK  passed to the .pfb loader (0x085b9400) by the resolver */
    uint32_t src_c;          /* +0x0c  ?  source ptr/id                                          */
    char    *face_name;      /* +0x10 OK  friendly face name ("Courier 10 Pitch","Bodoni-WP")   */
    char    *aux_name;       /* +0x14  ?  secondary/aux name (appended if present)              */
    struct wp_font_metric *rasterized; /* +0x18 OK  loaded resource: the metric struct, or 0    */
                                       /*           until this font is first used (lazy)        */
    uint16_t alias_index;    /* +0x1c OK  0xffff = self; else index of the record it aliases     */
    uint16_t _pad1e;         /* +0x1e  ?                                                         */
} wp_font_record;            /* sizeof == 0x20 */

/* --- Font metric struct: per loaded font. Pointed to by WP_CUR_METRIC and by an active
 * record's +0x18. Also reachable as wp_glyph_table.metric. Large (>0x5a0 bytes). ---------- */
typedef struct wp_font_metric {
    char    *ps_name;        /* +0x00 OK  PostScript face name ("Courier10PitchBT-Roman", with  */
                             /*           style suffix -Bold/-Italic — used for slant/weight)   */
    uint32_t p04;            /* +0x04  ?  ptr (binary blob live: leading 0x01)                  */
    uint32_t p08;            /* +0x08  ?  ptr                                                    */
    uint32_t v0c;            /* +0x0c  ?  non-pointer value                                      */
    /* ... unmapped ... */
    /* +0x5a0 OK  per-character width / AFM table (23 access sites in 8.0 .text). Element
     *            stride/type and the design-unit base (width*ptsize/3600, ~1000-em AFM)
     *            are (unconfirmed) — the metric-supplant work must read one live entry.
     *            ascent/descent/leading/kerning likely live nearby; field map (unconfirmed). */
} wp_font_metric;
#define WP_METRIC_WIDTHTAB_OFF 0x5a0

/* --- Font display context: built per font by 0x085b9a30, published at WP_CUR_CONTEXT. ---- */
typedef struct wp_font_context {
    uint32_t packed00;       /* +0x00  ?  live 0x02580001 (size<<16 | flags ?)                  */
    uint32_t packed04;       /* +0x04  ?  live 0x00100064                                        */
    uint32_t v08;            /* +0x08  ?  live 0                                                 */
    struct wp_glyph_table *glyph_table; /* +0x0c OK  == [WP_CUR_GLYPHTAB]                        */
    uint32_t v10, v14, v18;  /* +0x10..+0x18 ? live 0                                            */
    uint32_t code;           /* +0x1c  ?  live 0x0c11 — candidate current font code             */
    uint32_t v20, v24;       /* +0x20,+0x24 ? live 0                                             */
    struct wp_font_metric *metric;      /* +0x28 OK  == [WP_CUR_METRIC]                          */
    uint32_t v2c;            /* +0x2c  ? live 0                                                  */
} wp_font_context;

/* --- Glyph table: per font, holds the rasterized per-glyph pixmaps blitted by draw_text_run.
 * Published at WP_CUR_GLYPHTAB (== context->glyph_table). The header's +0x08 is the metric
 * struct. The per-glyph array layout is only partly pinned: the draw site (0x085b5916)
 * indexes with a 12-byte stride (glyph = tab[char]; pixmap = glyph->+0x18), yet the context
 * builder callocs 256*0x18 for it — reconcile before relying on the stride. (unconfirmed) */
typedef struct wp_glyph_table {
    uint32_t v00;            /* +0x00 ? live 0                                                   */
    uint32_t v04;            /* +0x04 ? live 0                                                   */
    struct wp_font_metric *metric; /* +0x08 OK  == [WP_CUR_METRIC]                               */
    /* per-glyph entries follow; stride 12 at the draw site (glyph->+0x18 = 1-bit Pixmap). */
} wp_glyph_table;

/* Per-glyph entry as indexed by the draw site (12-byte stride, glyph struct pointer first). */
typedef struct wp_glyph {
    void    *unk0;           /* +0x00 ?                                                          */
    void    *unk4;           /* +0x04 ?                                                          */
    void    *unk8;           /* +0x08 ?                                                          */
    /* the glyph STRUCT this points to has its 1-bit Pixmap at +0x18 (blitted via XCopyPlane) */
} wp_glyph;
#define WP_GLYPH_PIXMAP_OFF 0x18

/* ======================================================================================
 * Convenience accessors (read WP's live globals; caller must range-guard in the shim)
 * ==================================================================================== */
#define WP_G(addr, type)  (*(type *)(uintptr_t)(addr))
#define WP_font_array()   ((wp_font_record **)(uintptr_t)WP_G(WP_FONTREC_ARR, uint32_t))
#define WP_font_count()   WP_G(WP_FONTREC_CNT, uint16_t)
#define WP_cur_metric()   ((wp_font_metric  *)(uintptr_t)WP_G(WP_CUR_METRIC, uint32_t))
#define WP_cur_context()  ((wp_font_context *)(uintptr_t)WP_G(WP_CUR_CONTEXT, uint32_t))

#endif /* WP_FONTS_H */
