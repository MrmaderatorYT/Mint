#!/usr/bin/env python3
"""Draws a mint leaf as a clean SVG.

Written fresh rather than reusing the earlier generator, whose width profile made
a fat oval that no amount of decoration on top could turn back into a leaf. The
proportions here are the point:

* Length to width is about 2.3:1. The earlier attempt sat near 1.8:1, which is why
  it read as a blob.
* Widest at 40% up from the base, not at the middle — that asymmetry is what makes
  a shape ovate, and what separates a leaf from an ellipse.
* Both ends come to a point, the tip more sharply than the base.
* The margin is serrate. Mint is toothed, and a smooth outline reads as a generic
  leaf rather than this one.

The leaf is built on a vertical axis and tilted by a transform at the end. Drawing
it at an angle directly would mean every vein, tooth and stalk coordinate carried
the rotation, and changing the tilt would mean recomputing all of them.
"""

import math
import os

OUT = os.path.dirname(os.path.abspath(__file__))

BASE = (50.0, 93.0)
TIP = (50.0, 9.0)
HALF_WIDTH = 22.0
# Fraction of the way up at which the leaf is widest.
WIDEST = 0.40
# Lower is fuller; higher draws the ends out into longer points.
FULLNESS = 0.62

TEETH = 11
TOOTH_DEPTH = 2.0
STALK = 21.0

# Clockwise, so a leaf drawn pointing up ends up pointing up and to the right.
TILT = 40.0
# The ring is optional: it frames the mark but costs the leaf about a fifth of its
# size, which matters at icon sizes.
RING_RADIUS = 41.0
RING_WIDTH = 2.0
# How far from the centre the drawing may reach. The leaf plus its stalk is longer
# than the canvas, so without this the tip and the stalk run off the edge.
FIT_RADIUS = 45.0

LIGHT = '#7EE6A8'
DARK = '#1E9E62'
VEIN = '#127A4C'


def on_axis(s):
    return (BASE[0] + (TIP[0] - BASE[0]) * s, BASE[1] + (TIP[1] - BASE[1]) * s)


def half_width(s):
    if s <= 0.0 or s >= 1.0:
        return 0.0
    warped = s ** (math.log(0.5) / math.log(WIDEST))
    return HALF_WIDTH * math.sin(math.pi * warped) ** FULLNESS


def margin(s, side):
    cx, cy = on_axis(s)
    return (cx + half_width(s) * side, cy)


def outline():
    """Up one margin to the tip and back down the other, a tooth per curve.

    Each tooth is a quadratic whose control point is pushed out from the smooth
    profile and biased towards the tip, so the teeth lean forward the way a real
    serrate margin does instead of reading as a row of bumps.
    """
    parts = ['M {:.2f},{:.2f}'.format(*on_axis(0.0))]
    for side in (1, -1):
        first, last = (0.0, 1.0) if side == 1 else (1.0, 0.0)
        forward = 1.0 if side == 1 else -1.0
        for i in range(TEETH):
            s0 = first + (last - first) * i / TEETH
            s1 = first + (last - first) * (i + 1) / TEETH
            mid = (s0 + s1) / 2
            control = margin(mid, side)
            depth = TOOTH_DEPTH * math.sin(math.pi * mid) ** 0.5
            end = margin(s1, side) if 0.0 < s1 < 1.0 else on_axis(s1)
            parts.append('Q {:.2f},{:.2f} {:.2f},{:.2f}'.format(
                control[0] + depth * side,
                control[1] - depth * forward * 0.8,
                *end))
    parts.append('Z')
    return ' '.join(parts)


def veins():
    """Midrib plus laterals, each angled towards the tip as venation actually runs."""
    out = ['M {:.2f},{:.2f} L {:.2f},{:.2f}'.format(*on_axis(-STALK / 84.0),
                                                    *on_axis(0.93))]
    for s in (0.18, 0.34, 0.50, 0.66):
        start = on_axis(s)
        for side in (1, -1):
            edge = margin(min(0.94, s + 0.17), side)
            out.append('M {:.2f},{:.2f} Q {:.2f},{:.2f} {:.2f},{:.2f}'.format(
                *start,
                start[0] + (edge[0] - start[0]) * 0.45,
                start[1] + (edge[1] - start[1]) * 0.75,
                start[0] + (edge[0] - start[0]) * 0.84,
                start[1] + (edge[1] - start[1]) * 0.84))
    return out


def svg(background=None, ring=False):
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" '
             'width="100" height="100">',
             '<defs><linearGradient id="leaf" x1="30" y1="14" x2="72" y2="92" '
             'gradientUnits="userSpaceOnUse">'
             f'<stop offset="0" stop-color="{LIGHT}"/>'
             f'<stop offset="1" stop-color="{DARK}"/>'
             '</linearGradient></defs>']
    if background:
        parts.append(f'<rect width="100" height="100" fill="{background}"/>')
    if ring:
        parts.append(f'<circle cx="50" cy="50" r="{RING_RADIUS}" fill="none" '
                     f'stroke="{VEIN}" stroke-width="{RING_WIDTH}"/>')
    # Everything below is drawn upright, then centred, scaled to fit and tilted as
    # a whole. The content's midpoint is not the canvas centre — the stalk hangs
    # below the leaf — so it is shifted before scaling rather than after.
    tip_y = TIP[1]
    stalk_y = BASE[1] + STALK
    content_centre = (tip_y + stalk_y) / 2
    scale = FIT_RADIUS / ((stalk_y - tip_y) / 2)
    parts.append(f'<g transform="rotate({TILT} 50 50) translate(50 50) '
                 f'scale({scale:.4f}) translate(-50 {-content_centre:.2f})">')
    end = on_axis(-STALK / 84.0)
    parts.append(
        f'<path d="M {end[0]:.2f},{end[1]:.2f} '
        f'Q {BASE[0] - 1.6:.2f},{BASE[1] + STALK * 0.35:.2f} '
        f'{BASE[0]:.2f},{BASE[1] - 3:.2f}" fill="none" stroke="{DARK}" '
        'stroke-width="2.8" stroke-linecap="round"/>')
    parts.append(f'<path d="{outline()}" fill="url(#leaf)"/>')
    parts.append(f'<g fill="none" stroke="{VEIN}" stroke-width="1.5" '
                 'stroke-linecap="round" stroke-opacity="0.45">')
    for path in veins():
        parts.append(f'<path d="{path}"/>')
    parts.append('</g></g></svg>')
    return '\n'.join(parts)


def main():
    ratio = 84.0 / (2 * HALF_WIDTH)
    print(f'length:width = {ratio:.2f}:1, widest at {WIDEST:.0%} from the base')
    for name, kwargs in (('leaf.svg', {}),
                         ('leaf-dark.svg', {'background': '#0A0F14'}),
                         ('leaf-ring.svg', {'ring': True}),
                         ('leaf-ring-dark.svg', {'background': '#0A0F14', 'ring': True})):
        with open(os.path.join(OUT, name), 'w') as handle:
            handle.write(svg(**kwargs))
    print('wrote leaf.svg, leaf-dark.svg, leaf-ring.svg, leaf-ring-dark.svg')


if __name__ == '__main__':
    main()
