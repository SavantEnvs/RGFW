/*
 * fuzz_x11_events — core X11 events and window properties another X client sends to / sets on an RGFW
 * window, end to end.
 *
 * Path: RGFW_window_checkEvent -> RGFW_pollEvents -> RGFW_XHandleEvent: KeyPress / KeyRelease (key
 * repeat detection, RGFW_apiKeyToRGFW, key char lookup), ButtonPress / ButtonRelease (scroll and
 * button mapping into RGFW's mouse state), MotionNotify, EnterNotify / LeaveNotify, FocusIn / FocusOut,
 * Expose, ConfigureNotify, ReparentNotify, Map / Unmap, ClientMessage, and PropertyNotify ->
 * RGFW_window_isMinimized (WM_STATE) / RGFW_window_isMaximized (_NET_WM_STATE) -> RGFW_window_checkMode;
 * after the events the harness calls the public state getters (RGFW_window_isMaximized / isMinimized /
 * isFloating / isFullscreen, RGFW_isKeyDown, RGFW_isMouseDown), which read the properties the peer set.
 *
 * The peer is a second X client: it XSendEvent()s the input's events to the RGFW window and
 * XChangeProperty()s the input's property values onto it.
 *
 * Input: up to 48 records of 16 bytes:
 *   u8 kind   (index into k_kinds: an X event type, or PROP = set a property)
 *   u8 a      keycode / button / detail; for PROP: the property (index into the atom table)
 *   u8 b      for PROP: the property type (atom table index); ReparentNotify: parent choice
 *   u8 c      for PROP: format (%3 -> 8/16/32) and number of items (c >> 2, at most 32 bytes' worth)
 *   i16 x, i16 y, u16 w, u16 h (LE)
 *   u32 v (LE)  event state / time / ClientMessage data; for PROP: item seed
 *   PROP items: 32-bit items are atom_table[(v + i) % N] when the low bit of v is 0, else raw v + i.
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW context and window, the peer
 * connection. Reset per input: the properties the peer may set are deleted, the window's flags,
 * parent, size/position and close flag are restored to their post-creation values, the key and mouse
 * button state is cleared, and both event queues are drained before returning.
 *
 * Mayhem fuzzes the AFL front end (RGFW_MAYHEM_AFL, one process per input): a button number above 7
 * indexes RGFW's mouse-button state out of bounds and a format-8 _NET_WM_STATE makes
 * RGFW_window_isFloating read Atoms past the property, both reached within libFuzzer's start-up probe.
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
static volatile size_t g_sink;
static u32 g_flags0;
static Window g_parent0;
static i32 g_x0, g_y0, g_w0, g_h0;

#define PROP 0
static const int k_kinds[] = {
    PROP, KeyPress, KeyRelease, ButtonPress, ButtonRelease, MotionNotify, EnterNotify, LeaveNotify,
    FocusIn, FocusOut, Expose, ConfigureNotify, ReparentNotify, MapNotify, UnmapNotify, ClientMessage,
};
#define N_KINDS (sizeof(k_kinds) / sizeof(k_kinds[0]))

static const char *const k_atom_names[] = {
    "_NET_WM_STATE", "WM_STATE", "_NET_WM_STATE_MAXIMIZED_VERT", "_NET_WM_STATE_MAXIMIZED_HORZ",
    "_NET_WM_STATE_ABOVE", "_NET_WM_STATE_FULLSCREEN", "ATOM", "CARDINAL", "WM_DELETE_WINDOW",
    "WM_PROTOCOLS", "_NET_WM_NAME", "UTF8_STRING", "STRING", "_NET_WM_STATE_HIDDEN", "INTEGER", "WINDOW",
};
#define N_ATOMS (sizeof(k_atom_names) / sizeof(k_atom_names[0]))
static Atom g_atoms[N_ATOMS];
/* properties the peer may set (atom indexes); deleted after every input */
static const int k_props[] = {0, 1, 10};

static void consume_event(const RGFW_event *ev) {
    g_sink += (size_t)ev->type;
#ifdef RGFW_MAYHEM_SELFTEST
    switch (ev->type) {
        case RGFW_keyPressed: case RGFW_keyReleased:
            printf("key type=%d value=%d repeat=%d\n", (int)ev->type, (int)ev->key.value, (int)ev->key.repeat);
            break;
        case RGFW_mouseButtonPressed: case RGFW_mouseButtonReleased:
            printf("button type=%d value=%d\n", (int)ev->type, (int)ev->button.value);
            break;
        default: printf("event type=%d\n", (int)ev->type); break;
    }
#endif
}

static void rgfw_drain(void) {
    XSync(_RGFW->display, False);
    RGFW_event ev;
    while (RGFW_window_checkEvent(g_win, &ev)) consume_event(&ev);
}

static void events_init(void) {
    peer_start_xserver();
    if (RGFW_init("fuzz_x11_events", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    g_win = RGFW_createWindow("fuzz_x11_events", 0, 0, 200, 200, 0);
    if (!g_win) { fprintf(stderr, "RGFW_createWindow failed\n"); abort(); }
    g_peer = peer_open();
    for (size_t i = 0; i < N_ATOMS; i++) g_atoms[i] = XInternAtom(g_peer, k_atom_names[i], False);
    g_pw = XCreateSimpleWindow(g_peer, DefaultRootWindow(g_peer), 0, 0, 10, 10, 0, 0, 0);
    XSync(g_peer, False);
    rgfw_drain();
    g_flags0 = g_win->internal.flags;
    g_parent0 = g_win->src.parent;
    g_x0 = g_win->src.x; g_y0 = g_win->src.y; g_w0 = g_win->src.w; g_h0 = g_win->src.h;
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void set_prop(Window w, const uint8_t *r, uint32_t v) {
    Atom prop = g_atoms[k_props[r[1] % 3]];
    Atom type = g_atoms[r[2] % N_ATOMS];
    int format = (int[]){8, 16, 32}[r[3] % 3];
    size_t n = (size_t)(r[3] >> 2) % 33;
    if (format == 32) {
        long items[32];
        for (size_t i = 0; i < n; i++) items[i] = (v & 1) ? (long)(uint32_t)(v + i) : (long)g_atoms[(v + i) % N_ATOMS];
        XChangeProperty(g_peer, w, prop, type, 32, PropModeReplace, (const unsigned char *)items, (int)n);
    } else if (format == 16) {
        short items[32];
        for (size_t i = 0; i < n; i++) items[i] = (short)(v + i);
        XChangeProperty(g_peer, w, prop, type, 16, PropModeReplace, (const unsigned char *)items, (int)n);
    } else {
        unsigned char items[32];
        for (size_t i = 0; i < n; i++) items[i] = (unsigned char)(v + i);
        XChangeProperty(g_peer, w, prop, type, 8, PropModeReplace, items, (int)n);
    }
}

static void send_event(Window w, const uint8_t *r, int type) {
    int16_t x = (int16_t)rd16(r + 4), y = (int16_t)rd16(r + 6);
    uint16_t ww = rd16(r + 8), hh = rd16(r + 10);
    uint32_t v = rd32(r + 12);
    Window root = DefaultRootWindow(g_peer);
    XEvent e;
    memset(&e, 0, sizeof(e));
    e.type = type;
    e.xany.window = w;
    switch (type) {
        case KeyPress: case KeyRelease:
            e.xkey.root = root; e.xkey.time = v >> 8; e.xkey.x = x; e.xkey.y = y;
            e.xkey.state = v & 0xff; e.xkey.keycode = r[1]; e.xkey.same_screen = True;
            break;
        case ButtonPress: case ButtonRelease:
            e.xbutton.root = root; e.xbutton.time = v >> 8; e.xbutton.x = x; e.xbutton.y = y;
            e.xbutton.state = v & 0xff; e.xbutton.button = r[1]; e.xbutton.same_screen = True;
            break;
        case MotionNotify:
            e.xmotion.root = root; e.xmotion.x = x; e.xmotion.y = y; e.xmotion.state = v; e.xmotion.same_screen = True;
            break;
        case EnterNotify: case LeaveNotify:
            e.xcrossing.root = root; e.xcrossing.x = x; e.xcrossing.y = y; e.xcrossing.detail = r[1] % 5;
            e.xcrossing.mode = r[2] % 3; e.xcrossing.same_screen = True;
            break;
        case FocusIn: case FocusOut:
            e.xfocus.mode = r[1] % 4; e.xfocus.detail = r[2] % 8;
            break;
        case Expose:
            e.xexpose.x = x; e.xexpose.y = y; e.xexpose.width = ww; e.xexpose.height = hh; e.xexpose.count = r[1];
            break;
        case ConfigureNotify:
            e.xconfigure.event = w; e.xconfigure.x = x; e.xconfigure.y = y;
            e.xconfigure.width = ww; e.xconfigure.height = hh; e.xconfigure.border_width = r[1];
            break;
        case ReparentNotify:
            e.xreparent.event = w;
            e.xreparent.parent = (r[2] % 3 == 0) ? root : (r[2] % 3 == 1) ? g_pw : (Window)v;
            e.xreparent.x = x; e.xreparent.y = y;
            break;
        case MapNotify: case UnmapNotify:
            e.xmap.event = w;
            break;
        case ClientMessage:
            e.xclient.message_type = g_atoms[r[1] % N_ATOMS];
            e.xclient.format = 32;
            e.xclient.data.l[0] = (r[2] & 1) ? (long)g_atoms[v % N_ATOMS] : (long)v;
            e.xclient.data.l[1] = x; e.xclient.data.l[2] = y; e.xclient.data.l[3] = ww; e.xclient.data.l[4] = hh;
            break;
    }
    XSendEvent(g_peer, w, False, NoEventMask, &e);
}

static int events_one(const uint8_t *data, size_t size) {
    if (size < 16) return -1;
    Window w = g_win->src.window;

    for (size_t off = 0, rec = 0; rec < 48 && size - off >= 16; rec++, off += 16) {
        const uint8_t *r = data + off;
        int kind = k_kinds[r[0] % N_KINDS];
        if (kind == PROP) set_prop(w, r, rd32(r + 12));
        else send_event(w, r, kind);
        XSync(g_peer, False);
        rgfw_drain();
    }
    rgfw_drain();

    /* the public state getters read the window properties the peer set */
    RGFW_bool st[4] = { RGFW_window_isMaximized(g_win), RGFW_window_isMinimized(g_win),
                        RGFW_window_isFloating(g_win), RGFW_window_isFullscreen(g_win) };
    size_t down = 0;
    for (int k = 0; k < RGFW_keyFinal; k++) down += RGFW_isKeyDown((RGFW_key)k);
    for (int b = 0; b < RGFW_mouseFinal; b++) down += RGFW_isMouseDown((RGFW_mouseButton)b);
    g_sink += down + st[0] + st[1] + st[2] + st[3];
#ifdef RGFW_MAYHEM_SELFTEST
    printf("state maximized=%d minimized=%d floating=%d fullscreen=%d down=%zu\n",
           (int)st[0], (int)st[1], (int)st[2], (int)st[3], down);
#endif

    /* reset what this input may have changed */
    for (size_t i = 0; i < sizeof(k_props) / sizeof(k_props[0]); i++) XDeleteProperty(g_peer, w, g_atoms[k_props[i]]);
    XSync(g_peer, False);
    rgfw_drain();
    g_win->internal.flags = g_flags0;
    g_win->src.parent = g_parent0;
    g_win->src.x = g_x0; g_win->src.y = g_y0; g_win->src.w = g_w0; g_win->src.h = g_h0;
    RGFW_window_setShouldClose(g_win, RGFW_FALSE);
    RGFW_resetKey();
    memset(_RGFW->mouseButtons, 0, sizeof(_RGFW->mouseButtons));
    return 0;
}

#ifdef RGFW_MAYHEM_AFL
/* AFL front end (the binary Mayhem fuzzes): one input file per process, `fuzz_x11_events-afl <file>`. */
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
    events_init();
    events_one(buf, n);
    free(buf);
    return 0;
}
#else
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    events_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return events_one(data, size); }
#endif
