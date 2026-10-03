#!/usr/bin/env python3
"""Render launcher fallbacks and 512px PNG from the approved SVG geometry.

Requires rsvg-convert and cwebp. Run: python3 examples/make_icons.py
No colour-keying of the legacy PNG; every density is rendered from vectors.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import make_logo

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "app/src/main/res"
DENSITIES = (("mdpi", 48), ("hdpi", 72), ("xhdpi", 96),
             ("xxhdpi", 144), ("xxxhdpi", 192))


def render(source, target, size):
    subprocess.run(["rsvg-convert", "-w", str(size), "-h", str(size),
                    "-o", str(target), str(source)], check=True)


def main():
    for command in ("rsvg-convert", "cwebp"):
        if not shutil.which(command):
            raise SystemExit(f"Required renderer missing: {command}")
    make_logo.main()
    with tempfile.TemporaryDirectory(prefix="mint-icons-") as temporary:
        temp = Path(temporary)
        for density, size in DENSITIES:
            directory = RES / f"mipmap-{density}"
            directory.mkdir(parents=True, exist_ok=True)
            for name, source in (("ic_launcher", "logo-icon.svg"),
                                 ("ic_launcher_round", "logo-round.svg")):
                png = temp / f"{name}-{density}.png"
                render(ROOT / "examples" / source, png, size)
                subprocess.run(["cwebp", "-quiet", "-lossless", str(png),
                                "-o", str(directory / f"{name}.webp")], check=True)
            print(f"Rendered {density}: {size}x{size}")
        store = ROOT / "playstore"
        store.mkdir(exist_ok=True)
        # Full-bleed square; store/launcher applies its own mask.
        render(ROOT / "examples/logo-preview.svg", store / "icon-512.png", 512)
        shutil.copyfile(store / "icon-512.png", RES / "drawable/logo.png")
    print("Rendered playstore/icon-512.png and drawable/logo.png (512x512).")


if __name__ == "__main__":
    main()
