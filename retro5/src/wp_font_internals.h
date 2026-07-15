/* wp_font_internals.h — recovered WordPerfect 8.0 font-membership struct model
 * =============================================================================
 * SINGLE SOURCE OF TRUTH for the printer-font-resource + name-pool machinery
 * that governs font SELECTION (the "collapse to printer default" bug, §17.1 of
 * installer/wp81port/FONT-RENDERING-MAP.md and FONT-SELECT-SUBSTITUTION-HANDOFF.md).
 *
 * Consumed by BOTH:
 *   (a) Ghidra   — installer/wp81port/... imports the same structs to type the
 *       decompiler (ghidra_hl/wp_font_types.h is the parser-friendly twin).
 *   (b) retro5 C — the §17.1 membership-extension code that must build byte-exact
 *       entries.
 *
 * PROVENANCE: reverse-engineered 2026-07-14 from the INSTALLED 8.0 binary
 *   ~/.local/share/wordperfect/8.0/wpbin/xwp  (MD5 89781a856a505823ec2b0bcce3f61cad,
 *   8009812 bytes, non-PIE base 0x08048000).  NOTE: this is a DIFFERENT binary from
 *   the one previously in the Ghidra project (ghidra_hl/xwp, MD5 da8dbe..., which is
 *   actually WordPerfect 8.1).  All addresses below are 8.0.  Analyzed in the fresh
 *   Ghidra project ghidra_hl/ghidra_proj80 (program "xwp80").
 *
 * CONFIRMED = derived directly from disassembly/decompilation of the named function.
 * (guess)   = inferred, not yet pinned; flagged inline.
 */
#ifndef WP_FONT_INTERNALS_H
#define WP_FONT_INTERNALS_H

#include <stdint.h>

/* ======================================================================== *
 * 1. WpResContainer — the generic WP "resource container"                  *
 *    CONFIRMED from the init routine 0x0841fbe0 (called by the allocator    *
 *    resource_container_alloc 0x0841fb60) and the accessor family below.    *
 *                                                                           *
 *    It is a PAGED collection: a directory of page pointers (+0x00), each   *
 *    page holding `per_page` elements of `elem_size` bytes.  It is NOT a    *
 *    flat array — every access goes through the accessor 0x084200b0.        *
 *                                                                           *
 *    Allocator call:  resource_container_alloc(elem_size, chunk_bytes)      *
 *      0x08412b90 printer_fontres_alloc: alloc(0x74, 0x1d0)  -> 116-byte    *
 *          elements, 4 per 0x1d0-byte page.                                 *
 *      0x0840e4d0 namepool_build:        alloc(0x400,0x400) -> 1024-byte    *
 *          elements ("name blocks"), 1 per page.                            *
 * ======================================================================== */
typedef struct WpResContainer {      /* malloc(0x34) = 52 bytes */
    void    *pagedir;    /* +0x00 array of page base pointers (NULL until 1st grow) */
    uint32_t flag;       /* +0x04 alloc flag arg (0 or 1); ordered/owns (guess)     */
    uint32_t chunk_bytes;/* +0x08 page allocation size in bytes = max(elem,arg2)    */
    uint32_t _r0c;       /* +0x0c (0)                                               */
    uint32_t _r10;       /* +0x10 (0 at init; live printer-res =0x40) (guess: hi-water)*/
    uint32_t count;      /* +0x14 number of LIVE elements (bounds check: idx<count) */
    uint32_t capacity;   /* +0x18 allocated element slots (count<=capacity)         */
    uint32_t elem_size;  /* +0x1c bytes per element                                 */
    uint32_t per_page;   /* +0x20 elements per page = chunk_bytes/elem_size         */
    uint32_t cur_index;  /* +0x24 iterator: current element index                   */
    uint32_t page_base;  /* +0x28 iterator: first index of current page             */
    uint32_t page_last;  /* +0x2c iterator: last index of current page (clamped)    */
    void    *cur_elem;   /* +0x30 iterator/lock cache: ptr to current element       */
} WpResContainer;

/* Accessor / mutator primitives (all take WpResContainer* as arg1). 8.0 addrs: */
/*  0x084200b0  void* res_get_elem(c, uint idx, void** outlock)  -- element ptr, or 0 if idx>=count */
/*  0x08420140  void* wp_resource_get(c, uint idx)  -- thin wrapper: res_get_elem(c,idx,0)           */
/*  0x08420160  void  wp_resource_close(c, uint idx) -- release the lock taken by _get               */
/*  0x08420170  bool  res_seek(c, uint idx)          -- position cur_elem to element[idx]             */
/*  0x08420200  void  res_clear_cache(c)             -- cur_elem = 0                                  */
/*  0x08420220  bool  res_next(c)                    -- advance iterator, false at end                */
/*  0x084202a0  bool  res_seek2(c, uint idx)         -- seek variant used by inserts (guess)          */
/*  0x0841fb60  WpResContainer* resource_container_alloc(elem_size, chunk_bytes)                      */
/*  0x0841fbe0  void  resource_container_init(c, elem_size, chunk_bytes, flag)                        */
/*  0x0841fc60  void  resource_container_free(c)                                                      */
/*  0x0841fd40  bool  res_grow(c, char zeroed)       -- add one page, capacity += per_page            */
/*  0x0841fe50  bool  res_append(c, void* src_elem)  -- count++, memcpy(src,elem_size) into new slot. */
/*                                                      ** THE ADD PRIMITIVE **  src==0 => reserve only*/

/* ======================================================================== *
 * 2. WpNamePoolBlock — one 1024-byte element of the name pool               *
 *    Global name pool container:  *(WpResContainer**)0x08812f80             *
 *    CONFIRMED from namepool_build 0x0840e4d0 and namepool_add 0x0840e600.  *
 *                                                                           *
 *    Names are packed variable-length records; a face name is located by    *
 *    (block_index, byte_offset).  block[0x3fe] is the block's free pointer.  *
 *    Record layout at `block + offset`:                                     *
 *        +0x00 uint8  byte_len   (UTF-16 name length in BYTES; 0..0xfc)      *
 *        +0x01 uint8  _pad/flags (guess)                                     *
 *        +0x02 uint16 name[]     (UTF-16LE, byte_len bytes, NUL-terminated)  *
 *    => the UTF-16 string pointer is  block + offset + 2.                    *
 *    Block 0 is seeded with a 10-byte sentinel (block[0]=8, free=10).        *
 * ======================================================================== */
typedef struct WpNamePoolBlock {     /* 1024 bytes */
    uint8_t  data[0x3fe];  /* +0x000 packed [len:u8][pad:u8][utf16 name] records   */
    uint16_t free_off;     /* +0x3fe bytes used = offset of next free record       */
} WpNamePoolBlock;

/* namepool_add 0x0840e600(void* utf16name, uint16_t byte_len, uint16_t out[2], char append)
 *   -> bool. out[0]=block_index, out[1]=byte_offset. Dedups against existing names.
 *   utf16 name-compare helper: namepool_name_eq 0x0840e580.
 * The per-face (block_index, byte_offset) pair is what gets stored into the codemap
 * entry (+0x0a / +0x0c) and copied into the classify buf (+0x18 / +0x1a). */

/* ======================================================================== *
 * 3. WpFontSet — a font-set object: one element of the printer-font        *
 *    resource, selected by the token.                                       *
 *      printer-font resource : *(WpResContainer**)0x08812f90                *
 *      token (element select) : *(uint16_t*)0x08812f8c                      *
 *    res = wp_resource_get(0x08812f90, 0x08812f8c) yields this struct.       *
 *    CONFIRMED from font_printres_member 0x08417900, printer_font_resolver  *
 *    0x084156f0, and the face-add path 0x08416b10 / 0x08417500.             *
 *                                                                           *
 *    It holds THREE nested WpResContainers:                                 *
 *      +0x18 codemap  : indexed by (0xfff-code)&0xfff -> WpCodeMapEntry      *
 *      +0x1c entries  : font metric entries -> WpFontEntry (keyed by        *
 *                        codemap->entry_idx)                                *
 *      +0x20 by_name  : 12-byte name-dedup records (lazily alloc'd)         *
 * ======================================================================== */
typedef struct WpFontSet {
    uint16_t _r00;         /* +0x00 (guess)                                        */
    uint16_t count;        /* +0x02 number of faces in this set (0 => not built)   */
    uint8_t  _r04[0x14];   /* +0x04                                                */
    WpResContainer *codemap;   /* +0x18 code-index -> WpCodeMapEntry                */
    WpResContainer *entries;   /* +0x1c metric entries -> WpFontEntry               */
    WpResContainer *by_name;   /* +0x20 12-byte name-dedup table (alloc 0xc,0x78)   */
    /* ... more fields (guess) ... */
} WpFontSet;

/* ======================================================================== *
 * 4. WpCodeMapEntry — one 0xa8-byte element of WpFontSet.codemap (+0x18)    *
 *    CONFIRMED size 0xa8 from the memcpy at 0x08405a13 (font_add_face).     *
 *    Field offsets CONFIRMED from font_entry_load 0x08417840 and            *
 *    printer_font_resolver 0x084156f0.  This is THE struct whose presence   *
 *    at index (0xfff-code) makes a face a "member".                          *
 * ======================================================================== */
typedef struct WpCodeMapEntry {      /* 0xa8 = 168 bytes */
    uint16_t code_index;   /* +0x00 this entry's own code-index (== container idx) */
    uint16_t _r02;         /* +0x02                                                */
    int16_t  entry_idx;    /* +0x04 index into WpFontSet.entries (+0x1c)           */
    uint8_t  _r06[2];      /* +0x06                                                */
    uint16_t size_id;      /* +0x08 point-size id -> font_entry_load buf+0x02 arg1 */
    uint16_t name_block;   /* +0x0a name-pool BLOCK index   -> classify buf+0x18   */
    uint16_t name_offset;  /* +0x0c name-pool BYTE offset    -> classify buf+0x1a  */
    uint8_t  _r0e[6];      /* +0x0e  (+0x0e/+0x0f/+0x10 = weight/style sort keys)  */
    uint16_t size_denom;   /* +0x14 -> font_entry_load 3rd arg (scale denominator) */
    uint8_t  _r16[0x72];   /* +0x16                                                */
    uint8_t  attr88;       /* +0x88 -> classify buf+0x0f                           */
    uint8_t  _r89[0x1d];   /* +0x89                                                */
    uint16_t next_link;    /* +0xa6 sorted-list "next" link (0xffff = end)         */
} WpCodeMapEntry;

/* ======================================================================== *
 * 5. WpFontEntry — one element of WpFontSet.entries (+0x1c)                 *
 *    The per-face metric record.  Fields CONFIRMED from font_entry_load     *
 *    0x08417840 (copies entry -> classify buf) and 0x08416b10 (+0xe/+0xf/   *
 *    +0x10 weight/style used for sorted insert).  Full size (guess) ~0x13+. *
 * ======================================================================== */
typedef struct WpFontEntry {
    uint16_t _r00;         /* +0x00                                                */
    uint16_t f02;          /* +0x02 -> classify buf+0x04                           */
    uint16_t f04;          /* +0x04 -> classify buf+0x06                           */
    uint16_t f06;          /* +0x06 -> classify buf+0x08                           */
    uint16_t f08;          /* +0x08 -> classify buf+0x0a                           */
    uint8_t  f0a;          /* +0x0a -> classify buf+0x0e                           */
    uint8_t  _r0b;         /* +0x0b                                                */
    uint16_t f0c;          /* +0x0c -> classify buf+0x0c                           */
    uint8_t  f0e;          /* +0x0e weight  -> classify buf+0x10 (sort key)        */
    uint8_t  f0f;          /* +0x0f style   -> classify buf+0x11 (sort key)        */
    uint8_t  f10;          /* +0x10         -> classify buf+0x12 (sort key)        */
    uint8_t  f11;          /* +0x11         -> classify buf+0x13                   */
    uint8_t  f12;          /* +0x12         -> classify buf+0x14 (as u16)          */
    /* ... (guess) ... */
} WpFontEntry;

/* ======================================================================== *
 * 6. WpClassifyBuf — the ~0x28-byte record font_classify fills              *
 *    CONFIRMED from font_classify 0x0852a9c0 and font_entry_load 0x08417840.*
 * ======================================================================== */
typedef struct WpClassifyBuf {       /* >= 0x28 bytes; caller stack local */
    uint16_t f00;          /* +0x00                                                */
    uint16_t scale;        /* +0x02 = font_scale(codemap.size_id,300,size_denom)   */
    uint16_t f04;          /* +0x04 <- WpFontEntry+0x02                            */
    uint16_t f06;          /* +0x06 <- WpFontEntry+0x04                            */
    uint16_t f08;          /* +0x08 <- WpFontEntry+0x06                            */
    uint16_t f0a;          /* +0x0a <- WpFontEntry+0x08                            */
    uint16_t f0c;          /* +0x0c <- WpFontEntry+0x0c                            */
    uint8_t  f0e;          /* +0x0e <- WpFontEntry+0x0a                            */
    uint8_t  f0f;          /* +0x0f <- WpCodeMapEntry+0x88                         */
    uint8_t  f10;          /* +0x10 <- WpFontEntry+0x0e                            */
    uint8_t  f11;          /* +0x11 <- WpFontEntry+0x0f                            */
    uint8_t  f12;          /* +0x12 <- WpFontEntry+0x10                            */
    uint8_t  f13;          /* +0x13 <- WpFontEntry+0x11                            */
    uint16_t f14;          /* +0x14 <- WpFontEntry+0x12                            */
    uint8_t  cat16;        /* +0x16 category byte: 7=valid, 6=invalid              */
    uint8_t  cat17;        /* +0x17 category byte: 0x14=valid, 0x10=invalid        */
    uint16_t name_block;   /* +0x18 name-pool block index  <- codemap.name_block   */
    uint16_t name_offset;  /* +0x1a name-pool byte offset  <- codemap.name_offset  */
    uint32_t _r1c;         /* +0x1c (0)                                            */
    uint16_t _r20;         /* +0x20 (0)                                            */
    uint16_t _r22;         /* +0x22                                                */
    uint32_t _r24;         /* +0x24 (0)                                            */
} WpClassifyBuf;

/* ======================================================================== *
 * 7. WpFontRecord — 32-byte DISPLAY font record (unchanged from §17.2)      *
 *    The flat display table:  arr = *(WpFontRecord***)0x08808754 ;          *
 *    count u16 @0x0880875a ; remap u16[] @0x0880876c (idx=0xfff-code ->      *
 *    slot).  This is what retro5 injects into and what the resolver renders.*
 * ======================================================================== */
typedef struct WpFontRecord {        /* calloc(1,0x20) */
    uint16_t flags;        /* +0x00 bit 0x8000 printer/scalable; bit 0x20 alias set */
    uint16_t _r02;         /* +0x02                                                */
    uint16_t _r04;         /* +0x04                                                */
    uint16_t fontcode;     /* +0x06 this record's own 12-bit code                  */
    char    *pfb_path;     /* +0x08 Type1 .pfb the loader opens                    */
    char    *list_name;    /* +0x0c §16.2 blob-list name                           */
    char    *face_name;    /* +0x10 display/selector face name (resolver renders)  */
    char    *aux_name;     /* +0x14 aux/second name, or 0                          */
    uint32_t glyphcache;   /* +0x18 lazily-filled glyph cache (0 until resolved)   */
    uint16_t alias;        /* +0x1c 0xffff=self else index of aliased record       */
    uint8_t  category;     /* +0x1e §14 filter byte                                */
    uint8_t  _r1f;         /* +0x1f                                                */
} WpFontRecord;

/* ======================================================================== *
 * 8. Key globals (8.0)                                                      *
 * ======================================================================== */
/*  0x08808754  WpFontRecord**  display record table                          */
/*  0x0880875a  uint16_t        display record count                          */
/*  0x08808758  uint16_t        display record capacity                       */
/*  0x0880876c  uint16_t*       remap[] : idx(0xfff-code) -> display slot      */
/*  0x087bdfe2  uint16_t        free-code counter (next injectable code, dec)  */
/*  0x087bdfe4  uint32_t        PRINTER DEFAULT packed code (collapse target)  */
/*  0x08812f90  WpResContainer* printer-font resource                         */
/*  0x08812f8c  uint16_t        printer-font resource token (element select)  */
/*  0x08812f80  WpResContainer* name pool                                     */
/*  0x08812f9c  void*           current printer/device struct                 */
/*  0x08812f74  void*           font-state object (+0x98 active code,+0xbe res)*/
/*  0x087bddf8  WpResContainer* "base/display" font resource handle.  During  */
/*              font_code_to_record, resource_ctx_push 0x08531300 temporarily */
/*              copies 0x087bddf8/0x087bddfc INTO 0x08812f90/0x08812f8c, so   */
/*              font_printres_member checks membership against THIS resource, */
/*              then resource_ctx_pop 0x08531390 restores. (Confirmed swap;   */
/*              whether 0x087bddf8 aliases the printer resource in the common */
/*              case needs one live read — see §17.1 recipe.)                 */
/*  0x087bddfc  uint16_t        token paired with 0x087bddf8                   */

/* ======================================================================== *
 * 9. WpViewCursor — the document VIEW + text-CARET state                    *
 *    (§17.2 caret-metric RE, 2026-07-14; Xvfb live + Ghidra ghidra_proj80)  *
 *                                                                           *
 *    This is the struct the DOCUMENT CARET (the blinking insertion bar) is  *
 *    drawn from.  Recovered while chasing "injected-TTF caret lags the      *
 *    glyphs": the committed §17.2 reformat fix makes the GLYPHS advance on   *
 *    real FreeType widths (screen array DAT_087fe9b8), but the caret still   *
 *    sits ON the last wide glyph / overshoots thin ones — because the caret  *
 *    reads a DIFFERENT metric, the DOCUMENT cursor position, which is still  *
 *    summed from the placeholder .prs widths.                               *
 *                                                                           *
 *    THE CARET DRAW (CONFIRMED, live bt on :241):                            *
 *      caret_paint  0x08407170 (FUN_08407170) — draws the caret with        *
 *        XDrawLine(dpy, win, gc, px, y, px, y+h) where                       *
 *        px = doc_x_to_px(view, view->cursor_x - view->origin_x)             *
 *           = FUN_08421030(view, cursor_x - origin_x).                        *
 *      doc_x_to_px 0x08421030:  px = (docx + (view->px_div_x>>1)) /          *
 *                                     view->px_div_x   (& 0xffff).           *
 *      doc_y_to_px 0x08421110 (vertical twin; uses +0x4a / +0x4c).           *
 *      The blink handler re-invokes caret_paint at the SAME cursor_x, so     *
 *      caret movement (Home/End/arrows) does NOT recompute any width — it    *
 *      just re-reads view->cursor_x.  cursor_x is (re)computed only at       *
 *      REFORMAT: cursor_layout 0x0836faa0 (FUN_0836faa0) sums the per-char   *
 *      DOCUMENT design width FUN_08387e50 (= charwidth_lookup_lo 0x0837e6b0, *
 *      the placeholder .prs/.pfm width) over the run and stores the result   *
 *      into cursor_x via caret_paint's tail (0x084072ee: view+0x54=arg).     *
 *                                                                           *
 *    => The caret's width source is the DOCUMENT width model (also drives    *
 *       line-wrap, justification and the "Pos" readout), NOT the isolated    *
 *       "caret node" the earlier handoff assumed.  font_widthcache_fill      *
 *       0x0845bac0 / font_width_cachemgr 0x08456af0 / percharadvance_rd      *
 *       0x080e4fa0 are the font-PREVIEW combo path (callers: FUN_0842c020    *
 *       display metric provider; combo_preview_*), proven off the doc-caret  *
 *       path by live breakpoints — do NOT hook them for the caret.           *
 *                                                                           *
 *    Units: cursor_x / origin_x / cursor_y / cursor_h are DOCUMENT design    *
 *    units = 1/1200 inch, point size baked in (same unit as DAT_087fe9b8).   *
 *    px_div_x = design units per screen pixel (~12 at ~100dpi; live: Home    *
 *    cursor_x=1200 origin_x=0 -> px=100).                                    *
 * ======================================================================== */
typedef struct WpViewCursor {   /* size >= 0x70; only the caret-relevant fields pinned */
    uint8_t  _r00[0x24];
    uint16_t origin_x;    /* +0x24 view scroll origin X (doc units) — subtracted     */
    uint8_t  _r26[0x28-0x26];
    uint16_t origin_y;    /* +0x28 view scroll origin Y (doc units)                  */
    uint8_t  _r2a[0x44-0x2a];
    uint16_t px_div_x;    /* +0x44 doc units per pixel, horizontal (FUN_08421030 div)*/
    uint8_t  _r46[0x4a-0x46];
    uint16_t px_div_y;    /* +0x4a doc units per pixel, vertical  (FUN_08421110 div) */
    uint16_t px_mul_y;    /* +0x4c vertical scale multiplier      (FUN_08421110 mul) */
    uint8_t  _r4e[0x54-0x4e];
    uint16_t cursor_x;    /* +0x54 CARET X in doc units  ★ the caret's x source      */
    uint8_t  _r56[0x58-0x56];
    uint16_t cursor_y;    /* +0x58 caret top Y in doc units                          */
    uint8_t  _r5a[0x5c-0x5a];
    uint16_t cursor_h;    /* +0x5c caret height in doc units                         */
    uint8_t  _r5e[0x60-0x5e];
    int16_t  hide_count;  /* +0x60 caret suppress counter (>0 => skip draw)          */
    uint8_t  _r62[0x68-0x62];
    int32_t  line_mul;    /* +0x68 line-height multiplier (guess; FUN_082ea3c0)      */
    int16_t  valid_gate;  /* +0x6c must be >=0 to paint the caret                    */
    uint16_t mode;        /* +0x6e mode word (0x11 special-cased in caret_paint)     */
} WpViewCursor;

/* ======================================================================== *
 * 10. WpFontMetricObj — the per-(font,size) font-METRIC object              *
 *    (§17.3 document-width RE, 2026-07-14; Ghidra ghidra_proj80 + live gdb) *
 *                                                                           *
 *    THE single shared per-char advance-width source for the WHOLE document *
 *    layout.  Fetched per font code from the metric resource DAT_08812d64   *
 *    (fontres_seek 0x0841eed0 -> fontmetric_obj_lock 0x0841ecf0); its widths *
 *    are loaded from wp.drs (Display ReSource) lazily, per character-set     *
 *    block (charset_block_lazyload 0x0841eda0 / charset_block_read           *
 *    0x08405800), and built by fontmetric_obj_build 0x085b6120.             *
 *                                                                           *
 *    The +0x40 table is read at TWO different index regions (§17.3):        *
 *    (A) SEGMENTED — the leaf width_primitive 0x0841eab0(obj,cs,char,&out):  *
 *          idx = 0x80 + (char - first[charset]) + SUM(count[i], i<charset)   *
 *        used by glyphs/charwidth_lookup/cursor_layout/wrap (Pipeline 1).    *
 *    (B) FLAT — the doc-position accumulators read table[char] directly      *
 *          (raw byte 0x20..0x7e for charset 0), inline, NOT via the leaf:    *
 *          pos_scan_next_char 0x0837fc70 / pos_run_advance 0x08389e00 do     *
 *          DAT_08810e02 += ((u16*)*(obj+0x48))[char] + DAT_08810e52          *
 *        THIS builds the caret/Pos accumulator DAT_08810e02 (Pipeline 2).    *
 *      out = width_bits==0 ? ((u8*)table)[idx] : ((u16*)table)[idx]         *
 *    BOTH regions hold the SAME width for a char (table[0x4f]==table[0xaf]   *
 *    for 'O'), so a caret fix MUST overwrite BOTH — the first §17.3 try      *
 *    touched only (A) and the flat caret cell stayed placeholder.           *
 *    Consumers: caret (cursor_layout 0x0836faa0 + pos_scan_next_char/        *
 *    pos_run_advance -> DAT_08810e02 -> cursor_pos_read 0x083ce2e0),         *
 *    wrap/justification/Pos/pagination (reformat_width_sum 0x0836e680), and  *
 *    the screen glyph array (reformat_char_append 0x083fa990).              *
 *                                                                           *
 *    UPSTREAM (verified live; reconciled w/ af1d341): the table is FILLED by  *
 *    fontmetric_widthblock_build 0x085b5cb0 from the PRINTER RESOURCE         *
 *    default.prs (DAT_08812f90) keyed by the RESOLVED code — NOT from a .pfb  *
 *    and NOT from record+0x08. A non-member injected code COLLAPSES to the    *
 *    printer default DAT_087bdfe4 (0xfff=Bitstream Charter) [member test      *
 *    font_printres_member 0x08417900: 0xd6f<(code>>16&0xfff)<0x1000]. That is *
 *    why the table reads Charter (FreeSans 'O'=390=Charter WX731@32, '|'=267  *
 *    =WX500) even though record+0x08 = wphv (‖ WX260≈139≠267). Both Pipelines *
 *    share this one .prs upstream; the fix is a REAL-width .prs member entry  *
 *    for the injected code (or a hook on the widthblock build/read), NOT a    *
 *    synthetic-Type1 at record+0x08 (never read for widths).                  *
 *                                                                           *
 *    Value unit: WP DESIGN UNITS = 1/1200 inch, point size baked in (same   *
 *    as DAT_087fe9b8).  Live: FreeSans 12pt O=146 W=186 I=65 space=56.      *
 *                                                                           *
 *    Injected (TrueType) faces get their OWN object, distinct from any base  *
 *    font (live: Courier 0x97a8fd8 width_bits=0 first[0]=0; FreeSans        *
 *    0x9b34fd8 width_bits=1 first[0]=32), so retro5 overwrites the injected  *
 *    object's +0x40 table with real FreeType advances without touching base  *
 *    fonts (§17.3).  reformat_ctx+0x190 == this object == charwidth's        *
 *    DAT_088114d4 (all the same pointer — verified live).                    *
 * ======================================================================== */
typedef struct WpFontMetricObj {
    uint16_t _r00;          /* +0x00                                              */
    uint8_t  width_bits;    /* +0x02 0 => 8-bit width table; else 16-bit          */
    uint8_t  is_bitmap;     /* +0x03 nonzero => bitmap path (width_primitive_bitmap)*/
    uint16_t count[15];     /* +0x04 chars per character-set segment (…+0x04+cs*2)*/
    uint16_t first[15];     /* +0x22 first char code of each segment (u8 read)    */
    /* NB: WP reads first[] as *(char*)(obj+0x22+cs*2) — low byte only. count[15]  */
    /* + first[15] = 60 bytes span +0x04..+0x40, so width_table follows at +0x40.  */
    void    *width_table;   /* +0x40 THE per-char advance table (design units)    */
    uint16_t res_index;     /* +0x44 metric-resource element index (set on lock)  */
    uint16_t _r46;          /* +0x46                                              */
    void    *width_table2;  /* +0x48 aliases +0x40 while locked                   */
    int16_t  lock;          /* +0x4c lock/refcount; 0 => use +0x40 else +0x48     */
    /* ... +0x76 i16 per-charset lazy-load block id (-2 = not loaded);            */
    /*     +0x98 u8 flags (bit1 = space/remap path in charwidth_lookup) ...       */
} WpFontMetricObj;

/* Compute the width_table index the leaf width_primitive 0x0841eab0 uses for a
 * (charset, char) pair.  charset 0 (ASCII) is the common case: idx = 0x80 +
 * (char - first[0]).  Returns -1 if the char is outside the object's segment. */
static inline int wp_fontmetric_idx(const WpFontMetricObj *o, unsigned charset, unsigned ch) {
    unsigned base = 0x80, i;
    const uint8_t *cnt = (const uint8_t *)o + 0x04;
    const uint8_t *fst = (const uint8_t *)o + 0x22;
    unsigned first_cs = fst[charset * 2];
    unsigned rel = (ch - first_cs) & 0xff;
    if (charset >= 15) return -1;
    if (rel >= *(const uint16_t *)(cnt + charset * 2)) return -1;
    for (i = 0; i < charset; i++) base += *(const uint16_t *)(cnt + i * 2);
    return (int)(base + rel);
}

/* Pipeline-2 FLAT index: the doc-position accumulators (pos_scan_next_char 0x0837fc70,
 * pos_run_advance 0x08389e00) read the width table by the RAW char byte, not the segmented
 * width_primitive index.  For charset-0 chars, table[char] and table[wp_fontmetric_idx(o,0,char)]
 * hold the SAME value; a caret/Pos fix that overwrites the table must write BOTH cells. */
static inline int wp_fontmetric_flatidx(const WpFontMetricObj *o, unsigned ch) {
    (void)o; return (int)(ch & 0xff);
}

/* ======================================================================== *
 * 11. WpType1Font — the parsed Type1 OUTLINE object (record+0x08 .pfb)      *
 *     (§18 TTF-native RE, 2026-07-14; ghidra_proj80/xwp80 89781a)           *
 *                                                                           *
 *     Built by t1_parse_pfb 0x085c8e60 (0x11c bytes) from the .pfb that     *
 *     t1_pfb_load 0x085b9400 opens for record+0x08.  This is the DISPLAY/   *
 *     GLYPH-OUTLINE object ONLY: its charstrings feed the outline engine    *
 *     [0x08816110] via font_glyph_advance_get80 0x085c8540 -> glyphrec[0]   *
 *     (the DRAW advance, which retro5's cairo path overrides).  It is NOT    *
 *     the caret/layout width source (that is WpFontMetricObj from wp.drs,    *
 *     keyed by the RESOLVED code — see §10 and the doc width-model).  The    *
 *     .pfb NAME is used only to OPEN this file; it is never a wp.drs key.    *
 *                                                                           *
 *     Only the fields t1_parse_pfb touches are pinned (offsets confirmed     *
 *     from the decompile; interior of the eexec dicts not fully mapped).     *
 * ======================================================================== */
typedef struct WpType1Font {     /* alloc 0x11c via t1_parse_pfb */
    void    *priv;          /* +0x04 -> Private/blues sub-dict (0x1a0 B); count @+0x1c */
    void    *charstrings;   /* +0x08 -> charstrings blob (DAT_08816124 B)          */
    /* ... */
    uint8_t  flags;         /* +0x20 bit0 = Encoding==StandardEncoding; bit1 parse-warn; bit6 cleared */
    /* ... */
    void    *notdef_tbl;    /* +0x38 = &DAT_087c86f4 default (.notdef fill)        */
    int16_t  glyph_count;   /* +0x3c # charstrings/glyphs (0xe5=229 => full StdEnc fast-path) */
    /* ... */
    void   **charstr_by_gid;/* +0x40 charstring ptr per glyph index               */
    /* +0x44 ... */
    char   **name_by_gid;   /* +0x48 glyph-name ptr per glyph index (StandardEncoding order when full) */
    /* ... */
    void   **subrs;         /* +0x58 Subrs array; count @ (priv)+0x1c             */
    void   **charstr_by_code;/*+0x5c code->charstring[256]: built by matching StdEnc
                              *       names DAT_08733788 vs name_by_gid/charstr_by_gid */
    /* ... +0x118 = 1 (init marker) */
} WpType1Font;

/* MINIMUM synthetic Type1 stub (record+0x08 = a .ttf, hand back a fake Type1):
 *   t1_parse_pfb + t1_eexec_tokenize 0x085eaa50 must parse it (ret 0) and end with a
 *   non-empty CharStrings dict.  A usable stub is a valid (minimal) Type1 font program:
 *     clear header: %!PS-AdobeFont-1.0 ; /FontType 1 ; /FontMatrix [0.001 0 0 0.001 0 0] ;
 *                   /FontName ; /Encoding (StandardEncoding def, or 256 dup i /n put) ;
 *                   /FontBBox ; /PaintType 0 ;
 *     eexec section: /Private { /lenIV 4 /BlueValues[] /MinFeature{16 16} /password ... } ;
 *                    /CharStrings N dict dup begin  /.notdef {hsbw endchar} + one entry per
 *                    needed code, each charstring at minimum "<sbx> <wx> hsbw endchar".
 *   Missing/unparseable eexec or empty CharStrings -> t1_parse_pfb returns -3.  Because cairo
 *   draws and the caret uses wp.drs (not this file), the charstrings need no real outline and
 *   the hsbw width is cosmetic (it only reaches glyphrec[0], which retro5 overrides).            */

#endif /* WP_FONT_INTERNALS_H */
