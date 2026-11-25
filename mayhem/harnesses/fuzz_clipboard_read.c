/*
 * fuzz_clipboard_read — the CLIPBOARD contents another X client hands to RGFW.
 *
 * Path: RGFW_readClipboard -> RGFW_readClipboardPtr (X11) twice (size probe, then copy):
 * XConvertSelection -> wait for SelectionNotify -> XGetWindowProperty -> length math -> memcpy.
 *
 * The peer is another application that owns CLIPBOARD. It runs on its own thread with its own X
 * connection, because RGFW_readClipboardPtr blocks until the owner answers. Every SelectionRequest is
 * answered from the current input:
 *   byte 0: bits 0-1 property type (UTF8_STRING, STRING, TEXT, ATOM), bit 2 refuse (property None),
 *           bits 3-4 format (8, 16, 32, 8)
 *   rest:   the property data (an input with no data bytes is answered with a refusal; a 16/32-bit
 *           format with fewer bytes than one element still sends an empty property)
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW context, the peer thread and its
 * ownership of CLIPBOARD (RGFW never takes it here). RGFW's cached clipboard copy is replaced by each
 * read, and each answer is built only from the current input, so a result depends only on its input.
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
#include <pthread.h>
#include <stdint.h>

static int g_ready[2];
static const uint8_t *g_data;
static size_t g_size;
static Atom g_types[4];
static volatile size_t g_sink;

static void *peer_thread(void *arg) {
    Display *d = (Display *)arg;
    Window owner = XCreateSimpleWindow(d, DefaultRootWindow(d), 0, 0, 10, 10, 0, 0, 0);
    Atom clipboard = XInternAtom(d, "CLIPBOARD", False);
    g_types[0] = XInternAtom(d, "UTF8_STRING", False);
    g_types[1] = XA_STRING;
    g_types[2] = XInternAtom(d, "TEXT", False);
    g_types[3] = XA_ATOM;
    XSetSelectionOwner(d, clipboard, owner, CurrentTime);
    XSync(d, False);
    if (write(g_ready[1], "r", 1) != 1) abort(); /* ready */
    for (;;) {
        XEvent e;
        XNextEvent(d, &e);
        if (e.type != SelectionRequest) continue;
        XSelectionRequestEvent *r = &e.xselectionrequest;
        XEvent reply;
        memset(&reply, 0, sizeof(reply));
        reply.xselection.type = SelectionNotify;
        reply.xselection.requestor = r->requestor;
        reply.xselection.selection = r->selection;
        reply.xselection.target = r->target;
        reply.xselection.time = r->time;
        reply.xselection.property = r->property;

        const uint8_t *p = g_data;
        size_t n = g_size;
        if (!p || n < 2) {
            /* nothing to give beyond the control byte: the owner refuses the conversion */
            reply.xselection.property = None;
        } else {
            uint8_t ctl = p[0];
            p++; n--;
            int fmt = (ctl >> 3) & 3;
            fmt = fmt == 1 ? 16 : fmt == 2 ? 32 : 8;
            if (ctl & 4) {
                reply.xselection.property = None;
            } else if (fmt == 8) {
                XChangeProperty(d, r->requestor, r->property, g_types[ctl & 3], 8, PropModeReplace, p, (int)n);
            } else if (fmt == 16) {
                size_t cnt = n / 2;
                short *v = (short *)calloc(cnt + 1, sizeof(short));
                for (size_t i = 0; i < cnt; i++) v[i] = (short)(p[2 * i] | (p[2 * i + 1] << 8));
                XChangeProperty(d, r->requestor, r->property, g_types[ctl & 3], 16, PropModeReplace,
                                (const unsigned char *)v, (int)cnt);
                free(v);
            } else {
                size_t cnt = n / 4;
                long *v = (long *)calloc(cnt + 1, sizeof(long));
                for (size_t i = 0; i < cnt; i++)
                    v[i] = (long)((uint32_t)p[4 * i] | ((uint32_t)p[4 * i + 1] << 8) |
                                  ((uint32_t)p[4 * i + 2] << 16) | ((uint32_t)p[4 * i + 3] << 24));
                XChangeProperty(d, r->requestor, r->property, g_types[ctl & 3], 32, PropModeReplace,
                                (const unsigned char *)v, (int)cnt);
                free(v);
            }
        }
        XSendEvent(d, r->requestor, False, NoEventMask, &reply);
        XSync(d, False);
    }
    return NULL;
}

static void clipboard_init(void) {
    XInitThreads();
    peer_start_xserver();
    if (RGFW_init("fuzz_clipboard_read", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    Display *peer = peer_open();
    if (pipe(g_ready) != 0) abort();
    pthread_t t;
    if (pthread_create(&t, NULL, peer_thread, peer) != 0) abort();
    char c;
    if (read(g_ready[0], &c, 1) != 1) abort(); /* wait until the peer owns CLIPBOARD */
}

static int clipboard_one(const uint8_t *data, size_t size) {
    if (size > (1u << 20)) return -1; /* stay well inside the X request size limit */
    /* The peer thread only reads g_data while RGFW blocks waiting for its answer. */
    g_data = data;
    g_size = size;
    /* drop the copy cached by the previous input, so a failed read cannot return it */
    if (_RGFW->clipboard) { RGFW_FREE(_RGFW->clipboard); _RGFW->clipboard = NULL; }
    const RGFW_dataTransfer *t = RGFW_readClipboard(RGFW_dataText);
    if (t && t->data) {
        size_t s = 0;
        for (size_t i = 0; i < t->length; i++) s += (unsigned char)t->data[i];
        g_sink += s;
#ifdef RGFW_MAYHEM_SELFTEST
        printf("clipboard type=%d len=%zu data=[%.*s]\n", (int)t->type, t->length, (int)t->length, t->data);
#endif
    }
#ifdef RGFW_MAYHEM_SELFTEST
    else printf("clipboard none\n");
#endif
    g_data = NULL;
    g_size = 0;
    return 0;
}

#ifdef RGFW_MAYHEM_AFL
/*
 * AFL front end (the build's fuzz_clipboard_read-afl, the binary Mayhem fuzzes): one input file per
 * process, `fuzz_clipboard_read-afl <file>`. The forkserver forks before main, so every input gets a
 * fresh Xvfb, RGFW context and peer thread (an X connection cannot be shared across fork).
 * Why not libFuzzer for Mayhem: RGFW_readClipboardPtr crashes on any empty clipboard property
 * (known-findings/empty-property), which libFuzzer reaches from an empty corpus within a few
 * executions; in-process libFuzzer stops at that first crash and fails Mayhem's start-up probe.
 */
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
    clipboard_init();
    clipboard_one(buf, n);
    free(buf);
    return 0;
}
#else
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    clipboard_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return clipboard_one(data, size); }
#endif
