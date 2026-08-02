#!/usr/bin/env python3
"""Draws the Mint logo: a mint leaf whose veins are a control-flow graph.

The mark says two things at once. A leaf alone says only the name; a control-flow
graph is the visual language every reverse-engineering tool speaks, so the veins
are drawn as one — an entry block low on the midrib, a split, two branches, a join
near the tip. Someone who has never heard of this program sees a mint leaf; someone
who opens disassemblers for a living sees a function.

Two things the drawing has to get right:

* The boxes must be clearly fatter than the edges joining them. When they are not,
  the graph collapses into one abstract outline and reads as a molecule diagram
  rather than as blocks and control flow.

* Nothing is positioned in canvas coordinates. The drawing is fitted into the
  circle every launcher mask preserves, so the composition cannot drift outside it
  when a parameter changes.
"""

import math
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

CANVAS = 108.0
CENTRE = CANVAS / 2
# Radius of the circle adaptive-icon masks always keep: 66dp across of the 108dp
# canvas. The fit below targets this, leaving the rest as bleed.
SAFE_RADIUS = 33.0

BASE = (30.0, 84.0)
TIP = (62.0, 42.0)
HALF_WIDTH = 15.0
# Mint leaves are ovate — fullest below the middle, drawn out to a point.
WIDEST = 0.44
# Where the leaf is cut. Past this the tip is gone and blocks take over.

TEETH = 6
TOOTH_DEPTH = 2.2
STALK = 5.0

# Blocks placed along the axis by t, sized from the leaf's own width there.
# (t, sideways drift, size factor of local leaf width, spin, opacity)
# Blocks leaving the bite: (t along the axis, distance clear of the margin,
# size, spin, opacity). Sizes step down to read as motion away from the leaf.
# Where the solid half ends and the blocked half begins, measured along the axis.
BLOCKS_FROM = 0.50

# Blocks are not placed at fixed points. Each step along the axis is the size of
# the block just placed plus a gap, so they cannot overlap however the leaf's
# proportions change — spacing them by hand produced one merged pale wedge instead
# of a row of blocks.
# Nearly the full half-width, so the blocks rebuild the leaf's upper half
# rather than floating inside it.
BLOCK_FILL = 0.94
BLOCK_GAP = 1.7
# Two more have left the leaf entirely: (t, drift clear of the margin, size, spin).
STRAY = [
    (1.16, 3.4, 4.2, 22, 0.72),
    (1.31, 7.6, 3.0, -32, 0.48),
]

LEAF_LIGHT = '#9BF5BE'
LEAF_DARK = '#1FA268'
VEIN = '#0A4930'


def axis():
    dx, dy = TIP[0] - BASE[0], TIP[1] - BASE[1]
    length = math.hypot(dx, dy)
    unit = (dx / length, dy / length)
    return length, unit, (-unit[1], unit[0])


def on_axis(t):
    return (BASE[0] + (TIP[0] - BASE[0]) * t, BASE[1] + (TIP[1] - BASE[1]) * t)


def half_width(t):
    if t <= 0.0 or t >= 1.0:
        return 0.0
    warped = t ** (math.log(0.5) / math.log(WIDEST))
    return HALF_WIDTH * math.sin(math.pi * warped) ** 0.72


def margin(t, side):
    _, _, perp = axis()
    cx, cy = on_axis(t)
    w = half_width(t)
    return (cx + perp[0] * w * side, cy + perp[1] * w * side)


def leaf_path():
    """The whole leaf: sawtooth up one margin, round the point, back down the other."""
    _, unit, perp = axis()
    parts = ['M {:.2f},{:.2f}'.format(*margin(0.004, 1))]

    def tooth_run(side, t_from, t_to):
        forward = 1.0 if t_to > t_from else -1.0
        for i in range(TEETH):
            t0 = t_from + (t_to - t_from) * i / TEETH
            t1 = t_from + (t_to - t_from) * (i + 1) / TEETH
            apex_t = max(0.004, min(0.996, (t0 + t1) / 2))
            apex = margin(apex_t, side)
            depth = TOOTH_DEPTH * math.sin(math.pi * apex_t) ** 0.4
            parts.append('L {:.2f},{:.2f}'.format(
                apex[0] + perp[0] * depth * side + unit[0] * depth * forward * 0.7,
                apex[1] + perp[1] * depth * side + unit[1] * depth * forward * 0.7))
            parts.append('L {:.2f},{:.2f}'.format(*margin(max(0.004, min(0.996, t1)), side)))

    tooth_run(1, 0.004, 0.996)
    parts.append('L {:.2f},{:.2f}'.format(*on_axis(1.0)))
    tooth_run(-1, 0.996, 0.004)
    parts.append('L {:.2f},{:.2f}'.format(*on_axis(0.0)))
    parts.append('Z')
    return ' '.join(parts)


# The graph, in leaf coordinates: (t along the axis, sideways as a fraction of the
# leaf half-width there). An entry, a split, two branches, a join.
NODES = {
    'entry': (0.17, 0.0),
    'split': (0.38, 0.0),
    'left': (0.60, -0.60),
    'right': (0.60, 0.60),
    'join': (0.82, 0.0),
}
EDGES = (('entry', 'split'), ('split', 'left'), ('split', 'right'),
         ('left', 'join'), ('right', 'join'))
# Boxes have to be clearly fatter than the edges joining them, or the graph
# collapses into one abstract outline instead of reading as blocks.
NODE_W = 8.4
NODE_H = 5.4


def node_centre(name):
    t, across = NODES[name]
    _, _, perp = axis()
    centre = on_axis(t)
    offset = half_width(t) * across
    return (centre[0] + perp[0] * offset, centre[1] + perp[1] * offset)


def edges():
    """Edge paths between node centres, trimmed so they meet the box, not its middle."""
    out = []
    for a, b in EDGES:
        ax, ay = node_centre(a)
        bx, by = node_centre(b)
        dx, dy = bx - ax, by - ay
        length = math.hypot(dx, dy) or 1.0
        trim = NODE_H * 0.42
        out.append('M {:.2f},{:.2f} L {:.2f},{:.2f}'.format(
            ax + dx / length * trim, ay + dy / length * trim,
            bx - dx / length * trim, by - dy / length * trim))
    return out


def stalk_path():
    _, unit, _ = axis()
    start = (BASE[0] - unit[0] * STALK, BASE[1] - unit[1] * STALK)
    return 'M {:.2f},{:.2f} L {:.2f},{:.2f}'.format(*start, *on_axis(0.10))


def blocks():
    """The graph's basic blocks, as (cx, cy, width, height, spin)."""
    _, unit, _ = axis()
    angle = math.degrees(math.atan2(unit[1], unit[0]))
    return [node_centre(name) + (NODE_W, NODE_H, angle) for name in NODES]


def drawn_points():
    """Every extreme point of the drawing, for fitting."""
    points = []
    for i in range(1, 400):
        t = i / 400
        for side in (1, -1):
            m = margin(t, side)
            _, unit, perp = axis()
            points.append((m[0] + perp[0] * TOOTH_DEPTH * side,
                           m[1] + perp[1] * TOOTH_DEPTH * side))
    _, unit, _ = axis()
    points.append((BASE[0] - unit[0] * STALK, BASE[1] - unit[1] * STALK))
    for cx, cy, w, h, spin in blocks():
        rad = math.radians(spin)
        for sx, sy in ((-w / 2, -h / 2), (w / 2, -h / 2), (w / 2, h / 2), (-w / 2, h / 2)):
            points.append((cx + sx * math.cos(rad) - sy * math.sin(rad),
                           cy + sx * math.sin(rad) + sy * math.cos(rad)))
    return points


def fit_transform():
    """Scale and offset that put the whole drawing inside the mask-safe circle."""
    points = drawn_points()
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    cx, cy = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    radius = max(math.hypot(p[0] - cx, p[1] - cy) for p in points)
    scale = SAFE_RADIUS / radius
    return scale, CENTRE - cx * scale, CENTRE - cy * scale


def svg(background=None, monochrome=False, show_safe=False):
    scale, tx, ty = fit_transform()
    fill = '#000000' if monochrome else 'url(#leaf)'

    parts = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 108 108" '
             'width="108" height="108">']
    if not monochrome:
        parts.append(
            '<defs><linearGradient id="leaf" x1="24" y1="34" x2="76" y2="88" '
            'gradientUnits="userSpaceOnUse">'
            f'<stop offset="0" stop-color="{LEAF_LIGHT}"/>'
            f'<stop offset="1" stop-color="{LEAF_DARK}"/>'
            '</linearGradient></defs>')
    if background:
        parts.append(f'<rect width="108" height="108" fill="{background}"/>')
    if show_safe:
        parts.append(f'<circle cx="54" cy="54" r="{SAFE_RADIUS}" fill="none" '
                     'stroke="#ff0066" stroke-width="0.5" stroke-dasharray="2 2"/>')

    node_colour = '#000000' if monochrome else VEIN
    parts.append(f'<g transform="translate({tx:.3f} {ty:.3f}) scale({scale:.4f})">')
    if STALK > 0:
        parts.append(f'<path d="{stalk_path()}" fill="none" '
                     f'stroke="{"#000000" if monochrome else LEAF_DARK}" '
                     f'stroke-width="3.0" stroke-linecap="round"/>')
    parts.append(f'<path d="{leaf_path()}" fill="{fill}"/>')
    for path in edges():
        parts.append(f'<path d="{path}" fill="none" stroke="{node_colour}" '
                     'stroke-width="1.5" stroke-linecap="round"/>')
    for cx, cy, w, h, spin in blocks():
        parts.append(
            f'<rect x="{-w / 2:.2f}" y="{-h / 2:.2f}" width="{w:.2f}" height="{h:.2f}" '
            f'rx="{h * 0.28:.2f}" fill="{node_colour}" '
            f'transform="translate({cx:.2f} {cy:.2f}) rotate({spin:.2f})"/>')
    parts.append('</g></svg>')
    return '\n'.join(parts)


def rounded_rect(cx, cy, w, h, spin, transform):
    """A rounded square as pathData, rotated and fitted in place.

    VectorDrawable has no rect element, and baking the rotation into the points
    avoids relying on the order a <group> applies its transforms in.
    """
    r = min(w, h) * 0.28
    radians = math.radians(spin)

    def place(x, y):
        rx = x * math.cos(radians) - y * math.sin(radians)
        ry = x * math.sin(radians) + y * math.cos(radians)
        return transform((cx + rx, cy + ry))

    corners = [(-w / 2, -h / 2), (w / 2, -h / 2), (w / 2, h / 2), (-w / 2, h / 2)]
    parts = []
    for i in range(4):
        x0, y0 = corners[i]
        x1, y1 = corners[(i + 1) % 4]
        dx, dy = x1 - x0, y1 - y0
        length = math.hypot(dx, dy)
        ux, uy = dx / length, dy / length
        start = place(x0 + ux * r, y0 + uy * r)
        end = place(x1 - ux * r, y1 - uy * r)
        if i == 0:
            parts.append('M{:.2f},{:.2f}'.format(*start))
        else:
            parts.append('Q{:.2f},{:.2f} {:.2f},{:.2f}'.format(*place(x0, y0), *start))
        parts.append('L{:.2f},{:.2f}'.format(*end))
    parts.append('Q{:.2f},{:.2f} {:.2f},{:.2f}'.format(
        *place(*corners[0]), *place(corners[0][0] + r, corners[0][1])))
    parts.append('Z')
    return ' '.join(parts)


def retrace(path_d, transform):
    """Re-emits a generated path with the fit transform baked into every point."""
    out = []
    tokens = path_d.replace(',', ' ').split()
    i = 0
    while i < len(tokens):
        cmd = tokens[i]
        i += 1
        if cmd == 'Z':
            out.append('Z')
            continue
        count = {'M': 1, 'L': 1, 'Q': 2}[cmd]
        points = []
        for _ in range(count):
            x, y = float(tokens[i]), float(tokens[i + 1])
            i += 2
            points.append(transform((x, y)))
        out.append(cmd + ' '.join('{:.2f},{:.2f}'.format(*pt) for pt in points))
    return ' '.join(out)


def vector_drawable(monochrome=False):
    scale, tx, ty = fit_transform()

    def transform(point):
        return (point[0] * scale + tx, point[1] * scale + ty)

    fill_open, fill_close = '', ''
    if monochrome:
        fill_attr = ' android:fillColor="#FF000000"'
    else:
        fill_attr = ''
        fill_open = ('        <aapt:attr name="android:fillColor">\n'
                     '            <gradient android:type="linear"\n'
                     '                android:startX="24" android:startY="30"\n'
                     '                android:endX="80" android:endY="90"\n'
                     f'                android:startColor="{LEAF_LIGHT}"\n'
                     f'                android:endColor="{LEAF_DARK}" />\n'
                     '        </aapt:attr>\n')
        fill_close = ''

    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             '<!-- Generated by examples/make_logo.py. Edit that, not this. -->',
             '<vector xmlns:android="http://schemas.android.com/apk/res/android"',
             '    xmlns:aapt="http://schemas.android.com/aapt"',
             '    android:width="108dp" android:height="108dp"',
             '    android:viewportWidth="108" android:viewportHeight="108">']

    stalk_stroke = '#FF000000' if monochrome else LEAF_DARK
    if STALK > 0:
        lines.append('    <path android:pathData="{}"'.format(retrace(stalk_path(), transform)))
        lines.append(f'        android:strokeColor="{stalk_stroke}" '
                     f'android:strokeWidth="{3.0 * scale:.2f}" '
                     'android:strokeLineCap="round" />')

    lines.append('    <path android:pathData="{}"{}>'.format(
        retrace(leaf_path(), transform), fill_attr))
    if fill_open:
        lines.append(fill_open.rstrip('\n'))
    lines.append('    </path>')

    node_colour = '#FF000000' if monochrome else VEIN
    for path in edges():
        lines.append('    <path android:pathData="{}"'.format(retrace(path, transform)))
        lines.append(f'        android:strokeColor="{node_colour}" '
                     f'android:strokeWidth="{2.2 * scale:.2f}" '
                     'android:strokeLineCap="round" />')
    for cx, cy, w, h, spin in blocks():
        data = rounded_rect(cx, cy, w, h, spin, transform)
        lines.append(f'    <path android:pathData="{data}" '
                     f'android:fillColor="{node_colour}" />')
    lines.append('</vector>')
    text = '\n'.join(lines)
    return text


def main():
    scale, tx, ty = fit_transform()
    print(f'fit: scale {scale:.3f}, offset ({tx:.1f}, {ty:.1f}) — '
          f'bounding radius now exactly {SAFE_RADIUS}')
    out = os.path.join(ROOT, 'examples')
    for name, kwargs in (('logo.svg', {}),
                         ('logo-preview.svg', {'background': '#0A0F14'}),
                         ('logo-safe.svg', {'background': '#0A0F14', 'show_safe': True}),
                         ('logo-mono.svg', {'monochrome': True})):
        with open(os.path.join(out, name), 'w') as handle:
            handle.write(svg(**kwargs))
    print('wrote logo.svg, logo-preview.svg, logo-safe.svg, logo-mono.svg')

    drawable = os.path.join(ROOT, 'app', 'src', 'main', 'res', 'drawable')
    os.makedirs(drawable, exist_ok=True)
    with open(os.path.join(drawable, 'ic_launcher_foreground.xml'), 'w') as handle:
        handle.write(vector_drawable())
    with open(os.path.join(drawable, 'ic_launcher_monochrome.xml'), 'w') as handle:
        handle.write(vector_drawable(monochrome=True))
    print('wrote drawable/ic_launcher_foreground.xml, ic_launcher_monochrome.xml')


if __name__ == '__main__':
    main()
