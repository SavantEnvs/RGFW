# RGFW_readClipboardPtr (X11) reads before the property buffer when the clipboard is empty

- **Where:** `RGFW.h`, `RGFW_readClipboardPtr` (X11): `if (data[size - 1] != '\0') length += 1;`
  runs before anything checks `size`.
- **Trigger:** the CLIPBOARD owner answers the conversion with an empty property (zero items, any
  type/format). `XGetWindowProperty` returns `size == 0`, so `data[size - 1]` is `data[-1]`
  (UBSan pointer-overflow; with that check off, ASan heap-buffer-overflow on Xlib's 1-byte buffer).
  If the property is missing, `data` is NULL and the read is a NULL-1 dereference.
- **Impact:** any X client that owns the clipboard can crash an RGFW application that reads it.
- **Reproducer:** `crash-empty-16bit-property` (control byte `0x08` = 16-bit format, one data byte,
  so zero 16-bit items): `/mayhem/fuzz_clipboard_read-afl crash-empty-16bit-property` (or `/mayhem/fuzz_clipboard_read-standalone`).
- **Fix (one line):** return early when `size == 0 || data == NULL` (free `data`) before indexing.
