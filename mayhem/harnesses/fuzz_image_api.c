/*
 * fuzz_image_api — RGFW's pixel-data API: format conversion, window icons, custom cursors and
 * software surfaces, with caller-supplied pixels, size and format.
 *
 * Path: RGFW_copyImageData (-> RGFW_copyImageData64 / RGFW_convertImageData64 across the six
 * RGFW_format layouts), RGFW_window_setIconEx (X11: _NET_WM_ICON in the 64-bit long layout and the
 * icon pixmap), RGFW_createMouse / RGFW_window_setMouse / RGFW_freeMouse (XcursorImage), and
 * RGFW_createSurface / RGFW_window_blitSurface / RGFW_surface_free (XImage conversion + XPutImage).
 *
 * Input layout:
 *   u8 src format (%6)  u8 dst format (%6)  u8 w (%64 + 1)  u8 h (%64 + 1)  u8 ops
 *   then exactly w * h * channels(src format) pixel bytes (trailing bytes are ignored).
 * The API's contract is that the pixel buffer holds w * h pixels of the given format, so a shorter
 * input is rejected with -1. Pixels and the conversion destination are copied into buffers of exactly
 * that size, so any read or write past them is caught by ASan.
 * ops: bit 0 copyImageData, bits 1-2 setIconEx type (0 = none), bit 3 cursor, bit 4 surface.
 *
 * State kept across inputs, on purpose: the Xvfb server, the RGFW context and its window. Every
 * cursor and surface is freed in the same input; at the end of every input the _NET_WM_ICON property
 * is cleared (setIconEx with NULL), the icon pixmap RGFW leaves in the WM hints is freed and the
 * hint removed, and the X queue is drained.
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
static volatile size_t g_sink;

static void rgfw_drain(void) {
    XSync(_RGFW->display, False);
    RGFW_event ev;
    while (RGFW_window_checkEvent(g_win, &ev)) g_sink += (size_t)ev.type;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc; (void)argv;
    peer_start_xserver();
    if (RGFW_init("fuzz_image_api", 0) != 0) { fprintf(stderr, "RGFW_init failed\n"); abort(); }
    g_win = RGFW_createWindow("fuzz_image_api", 0, 0, 32, 32, 0);
    if (!g_win) { fprintf(stderr, "RGFW_createWindow failed\n"); abort(); }
    rgfw_drain();
    return 0;
}

static size_t channels(RGFW_format f) { return f >= RGFW_formatRGBA8 ? 4 : 3; }

#ifdef RGFW_MAYHEM_SELFTEST
static void print_bytes(const char *what, const uint8_t *p, size_t n) {
    printf("%s", what);
    for (size_t i = 0; i < n; i++) printf(" %02x", p[i]);
    printf("\n");
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return -1;
    RGFW_format sf = (RGFW_format)(data[0] % RGFW_formatCount);
    RGFW_format df = (RGFW_format)(data[1] % RGFW_formatCount);
    i32 w = data[2] % 64 + 1, h = data[3] % 64 + 1;
    uint8_t ops = data[4];
    size_t need = (size_t)w * (size_t)h * channels(sf);
    if (size - 5 < need) return -1; /* the API requires w * h pixels of format sf */

    uint8_t *src = (uint8_t *)malloc(need);
    memcpy(src, data + 5, need);

    if (ops & 1) {
        size_t dn = (size_t)w * (size_t)h * channels(df);
        uint8_t *dst = (uint8_t *)malloc(dn);
        memset(dst, 0xee, dn);
        RGFW_copyImageData(dst, w, h, df, src, sf, NULL);
        for (size_t i = 0; i < dn; i++) g_sink += dst[i];
#ifdef RGFW_MAYHEM_SELFTEST
        printf("convert %d->%d %dx%d\n", (int)sf, (int)df, w, h);
        print_bytes("  dst", dst, dn < 48 ? dn : 48);
#endif
        free(dst);
    }

    RGFW_icon icon = (RGFW_icon)((ops >> 1) & 3);
    if (icon) {
        RGFW_bool ok = RGFW_window_setIconEx(g_win, src, w, h, sf, icon);
        g_sink += ok;
#ifdef RGFW_MAYHEM_SELFTEST
        Atom type; int fmt; unsigned long n = 0, after; unsigned char *p = NULL;
        XGetWindowProperty(_RGFW->display, g_win->src.window, _RGFW->_NET_WM_ICON, 0, 64, False,
                           AnyPropertyType, &type, &fmt, &n, &after, &p);
        printf("icon type=%d ok=%d n=%lu", (int)icon, (int)ok, n);
        for (unsigned long i = 0; p && i < n && i < 6; i++) printf(" %08lx", ((unsigned long *)p)[i]);
        printf("\n");
        if (p) XFree(p);
#endif
    }

    if (ops & 8) {
        RGFW_mouse *m = RGFW_createMouse(src, w, h, sf);
        if (m) {
            RGFW_window_setMouse(g_win, m);
            RGFW_window_setMouseDefault(g_win);
            RGFW_freeMouse(m);
        }
#ifdef RGFW_MAYHEM_SELFTEST
        printf("cursor %s\n", m ? "created" : "none");
#endif
    }

    if (ops & 16) {
        RGFW_surface *s = RGFW_createSurface(src, w, h, sf);
        if (s) {
            RGFW_window_blitSurface(g_win, s);
#ifdef RGFW_MAYHEM_SELFTEST
            XImage *img = XGetImage(_RGFW->display, g_win->src.window, 0, 0, 1, 1, AllPlanes, ZPixmap);
            printf("surface pixel0=%06lx\n", img ? XGetPixel(img, 0, 0) & 0xffffff : 0UL);
            if (img) XDestroyImage(img);
#endif
            RGFW_surface_free(s);
        }
    }

    RGFW_window_setIconEx(g_win, NULL, 0, 0, RGFW_formatRGBA8, RGFW_iconTaskbar);
    /* RGFW_window_setIconEx(RGFW_iconWindow) never frees the icon pixmap it creates in the X server;
     * free it here so server memory does not grow with the number of inputs. */
    XWMHints *hints = XGetWMHints(_RGFW->display, g_win->src.window);
    if (hints) {
        if ((hints->flags & IconPixmapHint) && hints->icon_pixmap) {
            XFreePixmap(_RGFW->display, hints->icon_pixmap);
            hints->flags &= ~IconPixmapHint;
            hints->icon_pixmap = None;
            XSetWMHints(_RGFW->display, g_win->src.window, hints);
        }
        XFree(hints);
    }
    rgfw_drain();
    free(src);
    return 0;
}
