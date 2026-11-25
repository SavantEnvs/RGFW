/*
 * fuzz_xdnd_events — the XDND handshake and other client messages another X client sends to an RGFW
 * window, end to end.
 *
 * Path: RGFW_window_checkEvent -> RGFW_pollEvents -> RGFW_XHandleEvent (ClientMessage: XdndEnter with
 * inline types or the XdndTypeList property, XdndPosition, XdndLeave, XdndDrop -> XConvertSelection,
 * WM_PROTOCOLS / WM_DELETE_WINDOW) and, when RGFW asks for the drop data, SelectionNotify ->
 * RGFW_unix_parseURI -> RGFW_dataDropCallback.
 *
 * The peer client plays the drag source: it owns XdndSelection from its own source window, publishes
 * an XdndTypeList chosen by the input, sends the input's sequence of 32-bit client messages to the
 * RGFW window, and answers every SelectionRequest RGFW makes with the input's payload.
 *
 * Input layout:
 *   u8  ntypes (low 4 bits)      then ntypes x u8 atom index   -> XdndTypeList on the source window
 *   u16 payload length (LE)      then that many payload bytes -> served as the selection data
 *   then up to 32 records of 26 bytes:
 *     u8 message (index into the atom table: the ClientMessage message_type)
 *     5 x { u8 kind, u32 value (LE) }  -> data.l[i]: kind%4 = 0 raw value, 1 atom table[value],
 *                                          2 the source window, 3 the RGFW window
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW window, the peer connection and its
 * source window. Reset per input: the XdndTypeList property is replaced or deleted, RGFW's XDND session
 * (version/source/format, which an XdndEnter sets and which otherwise gates later messages) is cleared,
 * the window's close flag is cleared, and both event queues are drained before returning.
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
static Window g_src;
static Atom g_xdnd_selection, g_xdnd_typelist;
static volatile size_t g_sink;

static const char *const k_atom_names[] = {
    "XdndEnter", "XdndPosition", "XdndLeave", "XdndDrop", "XdndStatus", "XdndFinished",
    "WM_PROTOCOLS", "WM_DELETE_WINDOW", "text/uri-list", "text/plain", "UTF8_STRING", "STRING",
    "XdndActionCopy", "XdndTypeList", "XdndSelection", "_NET_WM_PING",
};
#define N_ATOMS (sizeof(k_atom_names) / sizeof(k_atom_names[0]))
static Atom g_atoms[N_ATOMS];

static const uint8_t *g_payload;
static size_t g_payload_len;

static void consume_event(const RGFW_event *ev) {
    if (ev->type == RGFW_dataDrop) {
        const RGFW_dataDropNode *n = ev->drop.value;
        if (n) { /* this event's own node (->next links the nodes of later events) */
            const unsigned char *p = (const unsigned char *)n->data;
            size_t s = 0;
            for (size_t i = 0; p && i < n->length; i++) s += p[i];
            g_sink += s;
#ifdef RGFW_MAYHEM_SELFTEST
            printf("drop type=%d len=%zu data=[%s]\n", (int)n->type, n->length, p ? (const char *)p : "(null)");
#endif
        }
    }
#ifdef RGFW_MAYHEM_SELFTEST
    else if (ev->type == RGFW_dataDrag) {
        printf("drag action=%d event=%d\n", (int)ev->drag.action, (int)ev->drag.type);
    } else if (ev->type == RGFW_windowClose) {
        printf("close\n");
    }
#endif
}

/* The drag source answers RGFW's request for the drop data. */
static void peer_service(void) {
    XSync(g_peer, False);
    while (XPending(g_peer)) {
        XEvent e;
        XNextEvent(g_peer, &e);
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
        XChangeProperty(g_peer, r->requestor, r->property, r->target, 8, PropModeReplace,
                        g_payload, (int)g_payload_len);
        XSendEvent(g_peer, r->requestor, False, NoEventMask, &reply);
    }
    XSync(g_peer, False);
}

static void rgfw_drain(void) {
    XSync(_RGFW->display, False);
    RGFW_event ev;
    while (RGFW_window_checkEvent(g_win, &ev)) consume_event(&ev);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    peer_start_xserver();
    if (RGFW_init("fuzz_xdnd_events", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    g_win = RGFW_createWindow("fuzz_xdnd_events", 0, 0, 200, 200, RGFW_windowAllowDND);
    if (!g_win) { fprintf(stderr, "RGFW_createWindow failed\n"); abort(); }
    g_peer = peer_open();
    for (size_t i = 0; i < N_ATOMS; i++) g_atoms[i] = XInternAtom(g_peer, k_atom_names[i], False);
    g_xdnd_selection = XInternAtom(g_peer, "XdndSelection", False);
    g_xdnd_typelist = XInternAtom(g_peer, "XdndTypeList", False);
    g_src = XCreateSimpleWindow(g_peer, DefaultRootWindow(g_peer), 0, 0, 10, 10, 0, 0, 0);
    XSetSelectionOwner(g_peer, g_xdnd_selection, g_src, CurrentTime);
    XSync(g_peer, False);
    rgfw_drain();
    return 0;
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t off = 0;
    if (size < 3) return -1;

    /* reset the XDND session and window state left by the previous input */
    _RGFW->x11Version = 0;
    _RGFW->x11Source = 0;
    _RGFW->x11Format = 0;
    _RGFW->x11TransferType = (RGFW_dataTransferType)0;
    RGFW_window_setShouldClose(g_win, RGFW_FALSE);

    size_t ntypes = data[off++] & 0x0f;
    if (ntypes > size - off) ntypes = size - off;
    if (ntypes) {
        long types[16];
        for (size_t i = 0; i < ntypes; i++) types[i] = (long)g_atoms[data[off + i] % N_ATOMS];
        XChangeProperty(g_peer, g_src, g_xdnd_typelist, XA_ATOM, 32, PropModeReplace,
                        (const unsigned char *)types, (int)ntypes);
    } else {
        XDeleteProperty(g_peer, g_src, g_xdnd_typelist);
    }
    off += ntypes;

    if (size - off < 2) return -1;
    size_t plen = (size_t)data[off] | ((size_t)data[off + 1] << 8);
    off += 2;
    if (plen > size - off) plen = size - off;
    g_payload = data + off;
    g_payload_len = plen;
    off += plen;

    Window w = g_win->src.window;
    for (int rec = 0; rec < 32 && size - off >= 26; rec++, off += 26) {
        const uint8_t *r = data + off;
        XEvent e;
        memset(&e, 0, sizeof(e));
        e.xclient.type = ClientMessage;
        e.xclient.window = w;
        e.xclient.message_type = g_atoms[r[0] % N_ATOMS];
        e.xclient.format = 32;
        for (int i = 0; i < 5; i++) {
            uint8_t kind = r[1 + i * 5] & 3;
            uint32_t v = rd32(r + 2 + i * 5);
            long val;
            switch (kind) {
                case 0: val = (long)v; break;
                case 1: val = (long)g_atoms[v % N_ATOMS]; break;
                case 2: val = (long)g_src; break;
                default: val = (long)w; break;
            }
            e.xclient.data.l[i] = val;
        }
        XSendEvent(g_peer, w, False, NoEventMask, &e);
        XSync(g_peer, False);
        rgfw_drain();
        peer_service();
        rgfw_drain();
    }
    peer_service();
    rgfw_drain();
    g_payload = NULL;
    g_payload_len = 0;
    return 0;
}
