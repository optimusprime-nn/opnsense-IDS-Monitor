"""Generate deploy/ipswatch.ico (shield) with Tk only - used by build.ps1."""
import struct
import sys
import tkinter as tk
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("ipswatch.ico"))
root = tk.Tk()
root.withdraw()

entries = []
for size in (16, 32, 48, 256):
    img = tk.PhotoImage(width=size, height=size)
    k = size / 32
    for y in range(int(2 * k), int(31 * k)):
        yy = y / k
        half = 13 if yy < 17 else 13 - (yy - 17) * 13 / 14
        if half > 0:
            img.put("#1f6feb", to=(int((16 - half) * k), y, int((16 + half) * k), y + 1))
    for y in range(size):  # transparent background outside the shield
        for x in range(size):
            if img.get(x, y) == (0, 0, 0):
                img.transparency_set(x, y, True)
    img.put("#ffffff", to=(int(14 * k), int(7 * k), int(18 * k), int(23 * k)))
    img.put("#ffffff", to=(int(9 * k), int(12 * k), int(23 * k), int(16 * k)))
    tmp = out.with_suffix(f".{size}.png")
    img.write(str(tmp), format="png")
    entries.append((size, tmp.read_bytes()))
    tmp.unlink()
root.destroy()

# ICO container with embedded PNGs (supported since Windows Vista).
header = struct.pack("<HHH", 0, 1, len(entries))
offset = 6 + 16 * len(entries)
dirs, blobs = b"", b""
for size, png in entries:
    dirs += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(png), offset)
    offset += len(png)
    blobs += png
out.write_bytes(header + dirs + blobs)
print(f"wrote {out}")
