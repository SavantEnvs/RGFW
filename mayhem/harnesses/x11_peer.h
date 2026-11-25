/*
 * Shared setup for the RGFW X11 harnesses.
 *
 * RGFW is a windowing library: on Linux, the only data it reads that it does not control comes from
 * other X clients through the X server (XDND drops, the CLIPBOARD selection, client messages). These
 * harnesses therefore run the real X11 backend against a private Xvfb server and act as a second X
 * client ("the peer") that delivers the fuzz bytes through the real protocol.
 *
 * Xvfb is started once per process (LLVMFuzzerInitialize). It picks a free display number itself
 * (-displayfd), so parallel fuzzer instances never collide, and it is killed when the fuzzer dies
 * (PR_SET_PDEATHSIG). If DISPLAY already names a reachable server, that server is used instead.
 */
#ifndef RGFW_MAYHEM_X11_PEER_H
#define RGFW_MAYHEM_X11_PEER_H

#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef XVFB_PATH
#define XVFB_PATH "/usr/bin/Xvfb"
#endif

static int peer_ignore_x_error(Display *d, XErrorEvent *e) { (void)d; (void)e; return 0; }

/* Start (or reuse) an X server and export DISPLAY. Aborts if no server can be reached. */
static void peer_start_xserver(void) {
    const char *cur = getenv("DISPLAY");
    if (cur && *cur) {
        Display *d = XOpenDisplay(cur);
        if (d) { XCloseDisplay(d); return; }
    }

    int fds[2];
    if (pipe(fds) != 0) { perror("pipe"); abort(); }
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); abort(); }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        close(fds[0]);
        char fdbuf[16];
        snprintf(fdbuf, sizeof(fdbuf), "%d", fds[1]);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) { dup2(devnull, 0); dup2(devnull, 1); dup2(devnull, 2); }
        execl(XVFB_PATH, "Xvfb", "-displayfd", fdbuf, "-nolisten", "tcp",
              "-screen", "0", "640x480x24", (char *)NULL);
        _exit(127);
    }
    close(fds[1]);
    char buf[32] = {0};
    size_t off = 0;
    while (off < sizeof(buf) - 1) {
        ssize_t n = read(fds[0], buf + off, sizeof(buf) - 1 - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        off += (size_t)n;
        if (memchr(buf, '\n', off)) break;
    }
    close(fds[0]);
    int num = atoi(buf);
    if (off == 0) { fprintf(stderr, "x11_peer: Xvfb did not start (%s)\n", XVFB_PATH); abort(); }
    char disp[32];
    snprintf(disp, sizeof(disp), ":%d", num);
    setenv("DISPLAY", disp, 1);
}

/* A second client connection: the "other application" whose data RGFW reads. */
static Display *peer_open(void) {
    Display *d = XOpenDisplay(NULL);
    if (!d) { fprintf(stderr, "x11_peer: cannot open %s\n", getenv("DISPLAY")); abort(); }
    return d;
}

#endif
