#!/usr/bin/env python3
"""Regenerates the launcher icon set from res/drawable/logo.png.

Checked in so the icons can be rebuilt when the logo changes, rather than being
a set of binaries nobody can reproduce.

Three things here are not obvious:

* The source logo is fully opaque — the black surround is baked into the pixels.
  An adaptive icon's foreground has to be transparent outside the artwork, or the
  launcher mask just shows a black tile, so the surround is keyed out. Keying is
  done on the *maximum* channel, not on brightness: the artwork contains a dark
  teal whose brightness sits inside any threshold that also removes the surround,
  and keying on brightness would leave that colour semi-transparent.

* The artwork is off-centre in the source (246px of margin on the left, 124px on
  the right). It is cropped to its own bounds before being re-centred, otherwise
  the icon sits visibly to one side.

* Adaptive icons are 108dp of canvas of which only the central ~66dp survives
  every launcher mask. The artwork is fitted to that, not to the full canvas.
"""

import os
from PIL import Image

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
RES = os.path.join(ROOT, 'app', 'src', 'main', 'res')
SOURCE = os.path.join(RES, 'drawable', 'logo.png')

# Density buckets: legacy launcher icon is 48dp, adaptive layers are 108dp.
DENSITIES = [('mdpi', 1), ('hdpi', 1.5), ('xhdpi', 2), ('xxhdpi', 3), ('xxxhdpi', 4)]

# Fraction of the 108dp adaptive canvas the artwork may occupy. 66/108 is the
# circle every mask keeps; a shade over it is fine here because the silhouette is
# an egg, so the corners the mask trims are empty anyway.
SAFE_FRACTION = 0.63

BACKGROUND = (0, 0, 0)


def keyed_artwork():
    """The logo cropped to its own bounds, with the black surround made transparent."""
    source = Image.open(SOURCE).convert('RGB')
    width, height = source.size
    pixels = source.load()

    out = Image.new('RGBA', (width, height))
    target = out.load()
    # Keyed on the strongest channel so a dark but saturated colour survives.
    low, high = 4, 22
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            level = max(r, g, b)
            if level <= low:
                alpha = 0
            elif level >= high:
                alpha = 255
            else:
                alpha = int(255 * (level - low) / (high - low))
            target[x, y] = (r, g, b, alpha)

    box = out.getbbox()
    return out.crop(box)


def monochrome_artwork(artwork):
    """A single-colour silhouette for Android 13+ themed icons.

    Built from the bright outline rather than the whole shape: an alpha mask of the
    entire egg would be a featureless blob, while the outline keeps the logo
    recognisable once the system replaces the colour.
    """
    width, height = artwork.size
    source = artwork.load()
    out = Image.new('RGBA', (width, height))
    target = out.load()
    low, high = 60, 140
    for y in range(height):
        for x in range(width):
            r, g, b, a = source[x, y]
            luminance = (r + g + b) / 3
            if a == 0 or luminance <= low:
                alpha = 0
            elif luminance >= high:
                alpha = 255
            else:
                alpha = int(255 * (luminance - low) / (high - low))
            target[x, y] = (0, 0, 0, alpha)
    return out


def centred(artwork, canvas_size, fraction, background=None):
    """Scales the artwork to `fraction` of the canvas and centres it."""
    limit = canvas_size * fraction
    scale = min(limit / artwork.width, limit / artwork.height)
    size = (max(1, round(artwork.width * scale)), max(1, round(artwork.height * scale)))
    scaled = artwork.resize(size, Image.LANCZOS)

    if background is None:
        canvas = Image.new('RGBA', (canvas_size, canvas_size), (0, 0, 0, 0))
    else:
        canvas = Image.new('RGBA', (canvas_size, canvas_size), background + (255,))
    canvas.paste(scaled, ((canvas_size - size[0]) // 2, (canvas_size - size[1]) // 2), scaled)
    return canvas


def circular(image):
    """Legacy round icon: the square icon clipped to a circle."""
    mask = Image.new('L', image.size, 0)
    from PIL import ImageDraw
    ImageDraw.Draw(mask).ellipse((0, 0, image.size[0] - 1, image.size[1] - 1), fill=255)
    out = image.copy()
    out.putalpha(mask)
    return out


def main():
    artwork = keyed_artwork()
    mono = monochrome_artwork(artwork)
    print(f'artwork cropped to {artwork.width}x{artwork.height}')

    for name, factor in DENSITIES:
        directory = os.path.join(RES, f'mipmap-{name}')
        os.makedirs(directory, exist_ok=True)

        # Adaptive layers: 108dp canvas.
        adaptive = round(108 * factor)
        centred(artwork, adaptive, SAFE_FRACTION).save(
            os.path.join(directory, 'ic_launcher_foreground.png'))
        centred(mono, adaptive, SAFE_FRACTION).save(
            os.path.join(directory, 'ic_launcher_monochrome.png'))

        # Legacy raster: 48dp, artwork on the background colour. Larger fraction
        # because nothing masks these beyond a rounded corner.
        legacy_size = round(48 * factor)
        legacy = centred(artwork, legacy_size, 0.92, background=BACKGROUND)
        legacy.convert('RGB').save(os.path.join(directory, 'ic_launcher.webp'),
                                   'WEBP', quality=95, method=6)
        circular(legacy).save(os.path.join(directory, 'ic_launcher_round.webp'),
                              'WEBP', quality=95, method=6)
        print(f'  {name}: adaptive {adaptive}px, legacy {legacy_size}px')

    # Play Console wants a 512x512 PNG with no alpha channel.
    store = os.path.join(ROOT, 'playstore')
    os.makedirs(store, exist_ok=True)
    centred(artwork, 512, 0.92, background=BACKGROUND).convert('RGB').save(
        os.path.join(store, 'icon-512.png'))
    print('  playstore/icon-512.png')


if __name__ == '__main__':
    main()
