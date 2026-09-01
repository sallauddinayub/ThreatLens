"""
Tiny dependency-free SVG chart helpers. No Chart.js/Recharts/D3 — these are
plain Python functions that return an <svg>...</svg> string the Jinja2
templates drop straight into the page. Keeps the whole frontend to
"HTML the server rendered," with zero JS build step.
"""
from __future__ import annotations

import math


def donut_chart(data: dict[str, int], colors: dict[str, str], size: int = 220, hole: float = 0.55) -> str:
    total = sum(data.values())
    if total == 0:
        return f'<svg width="{size}" height="{size}"></svg>'

    cx = cy = size / 2
    r = size / 2 - 4
    start_angle = -90.0
    paths = []

    for label, value in data.items():
        if value == 0:
            continue
        sweep = 360.0 * value / total
        end_angle = start_angle + sweep
        large_arc = 1 if sweep > 180 else 0

        x1 = cx + r * math.cos(math.radians(start_angle))
        y1 = cy + r * math.sin(math.radians(start_angle))
        x2 = cx + r * math.cos(math.radians(end_angle))
        y2 = cy + r * math.sin(math.radians(end_angle))

        color = colors.get(label, "#94a3b8")
        d = f"M {cx},{cy} L {x1:.2f},{y1:.2f} A {r},{r} 0 {large_arc} 1 {x2:.2f},{y2:.2f} Z"
        paths.append(f'<path d="{d}" fill="{color}"><title>{label}: {value}</title></path>')
        start_angle = end_angle

    hole_r = r * hole
    svg = [f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}">']
    svg.extend(paths)
    svg.append(f'<circle cx="{cx}" cy="{cy}" r="{hole_r:.2f}" fill="#ffffff" />')
    svg.append("</svg>")
    return "".join(svg)


def bar_chart(data: dict[str, int], colors: dict[str, str], width: int = 420, height: int = 220) -> str:
    """
    Renders a bar chart with an actual y-axis (gridlines + tick labels), not
    just floating bars — the previous version had no scale reference at all,
    just bar-top value labels and category names, which reads as "unlabeled"
    at a glance since there's nothing to compare bar heights against.
    """
    if not data:
        return f'<svg width="{width}" height="{height}"></svg>'

    max_val = max(data.values()) or 1
    # round the axis max up to a "nice" number so gridline labels aren't awkward fractions
    magnitude = 10 ** (len(str(int(max_val))) - 1)
    axis_max = math.ceil(max_val / magnitude) * magnitude
    if axis_max < max_val:
        axis_max += magnitude

    n = len(data)
    padding_left = 32
    padding_bottom = 28
    padding_top = 16
    plot_w = width - padding_left
    plot_h = height - padding_bottom - padding_top
    bar_w = (plot_w / n) * 0.55
    gap = (plot_w / n) * 0.45

    svg = [f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="IBM Plex Mono, monospace">']

    # y-axis gridlines + tick labels (0, 25%, 50%, 75%, 100% of axis_max)
    for frac in (0, 0.25, 0.5, 0.75, 1.0):
        y = height - padding_bottom - frac * plot_h
        tick_val = round(axis_max * frac)
        svg.append(f'<line x1="{padding_left}" y1="{y:.1f}" x2="{width}" y2="{y:.1f}" stroke="#e5edf9" stroke-width="1" />')
        svg.append(f'<text x="{padding_left - 6}" y="{y + 3:.1f}" font-size="9" fill="#7d90b3" text-anchor="end">{tick_val}</text>')

    # baseline (drawn on top of the 0% gridline for a crisper axis edge)
    svg.append(f'<line x1="{padding_left}" y1="{height - padding_bottom}" x2="{width}" y2="{height - padding_bottom}" stroke="#c3d3ec" stroke-width="1.25" />')

    for i, (label, value) in enumerate(data.items()):
        bar_h = (value / axis_max) * plot_h if axis_max else 0
        x = padding_left + i * (bar_w + gap) + gap / 2
        y = height - padding_bottom - bar_h
        color = colors.get(label, "#94a3b8")
        svg.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{bar_h:.1f}" rx="3" fill="{color}">'
            f"<title>{label}: {value}</title></rect>"
        )
        svg.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{height - padding_bottom + 14}" '
            f'font-size="10" fill="#3d5580" text-anchor="middle">{label}</text>'
        )
        svg.append(
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 4:.1f}" '
            f'font-size="10" fill="#122544" text-anchor="middle" font-weight="600">{value}</text>'
        )

    svg.append("</svg>")
    return "".join(svg)
