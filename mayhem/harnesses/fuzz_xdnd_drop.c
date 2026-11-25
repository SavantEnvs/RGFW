/*
 * fuzz_xdnd_drop — the XDND drop payload (text/uri-list) that another X client hands to an RGFW window.
 *
 * Path: RGFW_window_checkEvent -> RGFW_pollEvents -> RGFW_XHandleEvent (SelectionNotify for
 * XdndSelection) -> XGetWindowProperty -> RGFW_unix_parseURI -> RGFW_dataDropCallback -> event queue.
 * This is the code upstream fixed in 11d4f049 ("fix xdnd crash").
 *
 * Per input, the peer client (a second X connection, i.e. the drag source application) stores the
 * fuzz bytes as the XdndSelection property on the RGFW window with type text/uri-list — what a drag
 * source's selection reply does — and sends the SelectionNotify that completes the drop. RGFW then
 * reads and parses the property exactly as it would after a real drop.
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW window and the peer connection.
 * Each input replaces the property (PropModeReplace) and the event queue is drained before returning,
 * and the XDND version is never touched here (stays 0), so each input's result depends only on it.
 */
#define _GNU_SOURCE /* setenv, pipe, prctl in x11_peer.h */
#ifdef RGFW_MAYHEM_SELFTEST
/* zeroed allocations so the known-answer output never prints the bytes parseURI leaves unset */
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
static Atom g_xdnd_selection, g_uri_list;
static volatile size_t g_sink;

static void consume_drop(const RGFW_dataDropNode *node) {
    if (node) { /* this event's own node (->next links the nodes of later events) */
        const unsigned char *p = (const unsigned char *)node->data;
        size_t s = 0;
        for (size_t i = 0; p && i < node->length; i++) s += p[i];
        g_sink += s;
#ifdef RGFW_MAYHEM_SELFTEST
        /* known-answer output for mayhem/test.sh: the dropped string up to its terminator */
        printf("drop type=%d len=%zu data=[%s]\n", (int)node->type, node->length, p ? (const char *)p : "(null)");
#endif
    }
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    peer_start_xserver();
    if (RGFW_init("fuzz_xdnd_drop", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    g_win = RGFW_createWindow("fuzz_xdnd_drop", 0, 0, 200, 200, RGFW_windowAllowDND);
    if (!g_win) { fprintf(stderr, "RGFW_createWindow failed\n"); abort(); }
    g_peer = peer_open();
    g_xdnd_selection = XInternAtom(g_peer, "XdndSelection", False);
    g_uri_list = XInternAtom(g_peer, "text/uri-list", False);
    RGFW_event ev;
    XSync(_RGFW->display, False);
    while (RGFW_window_checkEvent(g_win, &ev)) {}
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > (1u << 20)) return -1; /* stay well inside the X request size limit */
    Window w = g_win->src.window;

    XChangeProperty(g_peer, w, g_xdnd_selection, g_uri_list, 8, PropModeReplace,
                    (const unsigned char *)data, (int)size);

    XEvent e;
    memset(&e, 0, sizeof(e));
    e.xselection.type = SelectionNotify;
    e.xselection.display = g_peer;
    e.xselection.requestor = w;
    e.xselection.selection = g_xdnd_selection;
    e.xselection.target = g_uri_list;
    e.xselection.property = g_xdnd_selection;
    e.xselection.time = CurrentTime;
    XSendEvent(g_peer, w, False, NoEventMask, &e);
    XSync(g_peer, False);

    XSync(_RGFW->display, False);
    RGFW_event ev;
    while (RGFW_window_checkEvent(g_win, &ev)) {
        if (ev.type == RGFW_dataDrop) consume_drop(ev.drop.value);
    }
    return 0;
}
