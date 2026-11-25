/*
 * fuzz_clipboard_serve — RGFW as the CLIPBOARD owner, answering selection requests from another X
 * client, end to end.
 *
 * Path: RGFW_writeClipboard (RGFW takes CLIPBOARD ownership) -> peer XConvertSelection ->
 * RGFW_window_checkEvent -> RGFW_pollEvents -> RGFW_XHandleEvent (SelectionRequest) ->
 * RGFW_XHandleClipboardSelection: TARGETS, MULTIPLE (reads the requestor's ATOM_PAIR property, whose
 * type, format and length the peer chooses), SAVE_TARGETS, UTF8_STRING / STRING.
 *
 * Input layout:
 *   u8 clipboard length L (>= 1), then L bytes   -> RGFW_writeClipboard
 *   then up to 16 requests:
 *     u8 target  (index into the atom table: the requested conversion target)
 *     u8 type    (index into the atom table: the type of the peer's request property)
 *     u8 format  (%3: 8, 16 or 32)
 *     u8 n       (number of items, at most 32)
 *     n items: 1 byte (format 8), 2 bytes (format 16), or 4 bytes (format 32, LE; when the top bit is
 *              set the item is atom_table[value % N], otherwise the raw value)
 *   Each request: the peer stores those items as the property FUZZ_PROP on its own window (deleted
 *   when n is 0), asks RGFW to convert CLIPBOARD to the target into FUZZ_PROP, RGFW serves it, the
 *   peer reads every SelectionNotify and the property RGFW wrote back.
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW context and window, the peer
 * connection and its window. Reset per input: RGFW_writeClipboard replaces RGFW's clipboard data
 * (and re-takes ownership), FUZZ_PROP is rewritten or deleted per request, and both event queues are
 * drained before returning.
 *
 * Mayhem fuzzes the AFL front end (RGFW_MAYHEM_AFL, one process per input): an odd-length or
 * format-8 ATOM_PAIR list makes RGFW_XHandleClipboardSelection read past the property it fetched,
 * which libFuzzer hits within its start-up probe.
 */
#define _GNU_SOURCE /* setenv, pipe, prctl in x11_peer.h */
#ifdef RGFW_MAYHEM_SELFTEST
#include <stdlib.h>
#define RGFW_ALLOC(n) calloc(1, (n))
#define RGFW_FREE(p) free(p)
#endif
#define RGFW_IMPLEMENTATION
#include "../../RGFW.h"

#include "x11_peer.h"
#include <stdint.h>

static RGFW_window *g_win;
static Display *g_peer;
static Window g_pw;
static Atom g_clipboard, g_prop;
static volatile size_t g_sink;

static const char *const k_atom_names[] = {
    "TARGETS", "MULTIPLE", "SAVE_TARGETS", "UTF8_STRING", "STRING", "ATOM_PAIR", "ATOM", "TEXT",
    "text/plain", "INTEGER", "FUZZ_PROP", "FUZZ_A", "FUZZ_B", "CLIPBOARD", "WINDOW", "None",
};
#define N_ATOMS (sizeof(k_atom_names) / sizeof(k_atom_names[0]))
static Atom g_atoms[N_ATOMS];

static void rgfw_drain(void) {
    XSync(_RGFW->display, False);
    RGFW_event ev;
    while (RGFW_window_checkEvent(g_win, &ev)) g_sink += (size_t)ev.type;
}

static const char *atom_label(Atom a) {
    for (size_t i = 0; i < N_ATOMS; i++) if (g_atoms[i] == a) return k_atom_names[i];
    return a == None ? "0" : "?";
}

/* Read back what RGFW stored on the peer window for one property. */
static void peer_read_prop(Atom prop) {
    Atom type = None; int fmt = 0; unsigned long n = 0, after = 0; unsigned char *p = NULL;
    if (XGetWindowProperty(g_peer, g_pw, prop, 0, 4096, False, AnyPropertyType, &type, &fmt, &n,
                           &after, &p) != Success) return;
    size_t unit = fmt == 32 ? sizeof(long) : fmt == 16 ? sizeof(short) : 1;
    for (size_t i = 0; p && i < n * unit; i++) g_sink += p[i];
#ifdef RGFW_MAYHEM_SELFTEST
    printf("  prop %s type=%s format=%d n=%lu", atom_label(prop), atom_label(type), fmt, n);
    if (p && fmt == 8) printf(" data=[%.*s]", (int)n, (const char *)p);
    if (p && fmt == 32) for (unsigned long i = 0; i < n; i++) printf(" %s", atom_label((Atom)((long *)p)[i]));
    printf("\n");
#endif
    if (p) XFree(p);
}

static void peer_drain(void) {
    XSync(g_peer, False);
    while (XPending(g_peer)) {
        XEvent e;
        XNextEvent(g_peer, &e);
        if (e.type != SelectionNotify) continue;
#ifdef RGFW_MAYHEM_SELFTEST
        printf("notify target=%s property=%s\n", atom_label(e.xselection.target),
               atom_label(e.xselection.property));
#endif
        if (e.xselection.property == None) continue;
        peer_read_prop(e.xselection.property);
        if (e.xselection.target == g_atoms[1]) { /* MULTIPLE: also read the per-pair properties */
            peer_read_prop(g_atoms[11]);
            peer_read_prop(g_atoms[12]);
        }
    }
}

static void serve_init(void) {
    peer_start_xserver();
    if (RGFW_init("fuzz_clipboard_serve", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    g_win = RGFW_createWindow("fuzz_clipboard_serve", 0, 0, 200, 200, 0);
    if (!g_win) { fprintf(stderr, "RGFW_createWindow failed\n"); abort(); }
    g_peer = peer_open();
    for (size_t i = 0; i < N_ATOMS; i++) g_atoms[i] = XInternAtom(g_peer, k_atom_names[i], False);
    g_atoms[15] = None;
    g_clipboard = XInternAtom(g_peer, "CLIPBOARD", False);
    g_prop = g_atoms[10];
    g_pw = XCreateSimpleWindow(g_peer, DefaultRootWindow(g_peer), 0, 0, 10, 10, 0, 0, 0);
    XSync(g_peer, False);
    rgfw_drain();
}

static int serve_one(const uint8_t *data, size_t size) {
    size_t off = 0;
    if (size < 1) return -1;
    size_t len = data[off++];
    if (len == 0 || len > size - off) return -1; /* RGFW_writeClipboard reads data[length - 1] */
    RGFW_dataTransfer clip = { (const char *)(data + off), len, RGFW_dataText };
    off += len;
    if (!RGFW_writeClipboard(&clip)) return 0;
    XSync(_RGFW->display, False);

    for (int req = 0; req < 16 && size - off >= 4; req++) {
        Atom target = g_atoms[data[off] % N_ATOMS];
        Atom type = g_atoms[data[off + 1] % N_ATOMS];
        int format = (int[]){8, 16, 32}[data[off + 2] % 3];
        size_t n = data[off + 3] % 33;
        off += 4;
        size_t unit = (size_t)format / 8;
        if (n > (size - off) / unit) n = (size - off) / unit;
        if (n == 0) {
            XDeleteProperty(g_peer, g_pw, g_prop);
        } else if (format == 32) {
            long items[32];
            for (size_t i = 0; i < n; i++) {
                const uint8_t *p = data + off + i * 4;
                uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
                items[i] = (v & 0x80000000u) ? (long)g_atoms[v % N_ATOMS] : (long)v;
            }
            XChangeProperty(g_peer, g_pw, g_prop, type, 32, PropModeReplace, (const unsigned char *)items, (int)n);
        } else if (format == 16) {
            short items[32];
            for (size_t i = 0; i < n; i++) items[i] = (short)(data[off + 2 * i] | (data[off + 2 * i + 1] << 8));
            XChangeProperty(g_peer, g_pw, g_prop, type, 16, PropModeReplace, (const unsigned char *)items, (int)n);
        } else {
            XChangeProperty(g_peer, g_pw, g_prop, type, 8, PropModeReplace, data + off, (int)n);
        }
        off += n * unit;
#ifdef RGFW_MAYHEM_SELFTEST
        printf("request target=%s proptype=%s format=%d n=%zu\n", atom_label(target), atom_label(type), format, n);
#endif
        XConvertSelection(g_peer, g_clipboard, target, g_prop, g_pw, CurrentTime);
        XSync(g_peer, False);
        rgfw_drain();
        peer_drain();
    }
    rgfw_drain();
    peer_drain();
    return 0;
}

#ifdef RGFW_MAYHEM_AFL
/* AFL front end (the binary Mayhem fuzzes): one input file per process, `fuzz_clipboard_serve-afl <file>`. */
int main(int argc, char **argv) {
    FILE *f = argc > 1 ? fopen(argv[1], "rb") : stdin;
    if (!f) { perror(argv[1]); return 1; }
    size_t cap = 1u << 16, n = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    for (;;) {
        if (n == cap) { cap *= 2; buf = (uint8_t *)realloc(buf, cap); }
        size_t r = fread(buf + n, 1, cap - n, f);
        if (r == 0) break;
        n += r;
    }
    if (f != stdin) fclose(f);
    serve_init();
    serve_one(buf, n);
    free(buf);
    return 0;
}
#else
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    serve_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return serve_one(data, size); }
#endif
