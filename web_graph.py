"""
Renders the asset graph (Section 7) as plain SVG computed server-side, with
a tiny vanilla-JS click handler (see static/app.js) that reads embedded
per-node JSON to populate the detail panel — no ReactFlow, no bundler.

Node styling carries real information, not just decoration: Critical/High
criticality assets render as filled circles (visually prominent); Medium/Low
render as outlined circles. Edges are drawn as gentle curves rather than
straight lines so a busy graph reads more like an architecture diagram and
less like a wiring schematic.
"""
from __future__ import annotations

import json
from xml.sax.saxutils import escape as _xml_escape

TYPE_COLORS = {
    "Web Application": "#2563eb",
    "API": "#3b82f6",
    "Authentication Service": "#0d9488",
    "Database": "#c0293c",
    "Payment Service": "#b45309",
    "External API": "#7c3aed",
    "Cloud Service": "#0891b2",
    "Monitoring Service": "#65a30d",
    "Storage": "#64748b",
    "User": "#94a3b8",
    "Admin": "#334155",
}

TIERS = {
    "User": 0, "Admin": 0,
    "Web Application": 1,
    "Authentication Service": 2, "API": 2, "External API": 2,
    "Payment Service": 3, "Database": 3, "Storage": 3, "Cloud Service": 3, "Monitoring Service": 3,
}

NODE_SPACING = 210   # horizontal space reserved per node within a tier
TIER_HEIGHT = 170
NODE_RADIUS = 27
TOP_MARGIN = 60
SIDE_PADDING = 110


def _initials(name: str) -> str:
    parts = name.split()
    return "".join(p[0] for p in parts)[:3].upper()


def _truncate(name: str, max_len: int = 24) -> str:
    return name if len(name) <= max_len else name[: max_len - 1] + "…"


def _safe(text: str) -> str:
    """
    Escapes &, <, > before embedding real (user-supplied) asset data into
    raw SVG markup. Asset names originate from uploaded OpenAPI specs,
    architecture text, or manual entry — all untrusted input — and this
    SVG is rendered with Jinja's `| safe` filter (bypassing HTML
    auto-escaping) so it can display as an actual inline diagram. Without
    this, a crafted asset name like '</text><script>...' would inject a
    real, executing script tag into the page (confirmed exploitable).
    """
    return _xml_escape(str(text))


def _json_for_script(data) -> str:
    """
    json.dumps() does not escape '/', so a value containing the literal
    text '</script>' would prematurely close the <script> tag this JSON
    is embedded in via `| safe`, letting an attacker inject arbitrary HTML
    after it (confirmed exploitable). Escaping every '/' as '\\/' is a
    JSON-spec-valid escape sequence, so JSON.parse() still reads it back
    correctly as a literal '/', while '</script>' can never appear as a
    literal substring in the emitted markup.
    """
    return json.dumps(data).replace("/", "\\/")


def build_asset_graph(assets: list[dict]) -> tuple[str, str, int]:
    """
    Returns (svg_markup, node_metadata_json, has_front_tier).
    node_metadata_json is embedded in the page as JSON and read by app.js
    on click to populate the inspector panel without a network round-trip.
    """
    by_tier: dict[int, list[dict]] = {}
    for a in assets:
        tier = TIERS.get(a["type"], 2)
        by_tier.setdefault(tier, []).append(a)

    max_per_tier = max((len(v) for v in by_tier.values()), default=1)
    width = max(900, max_per_tier * NODE_SPACING + SIDE_PADDING * 2)
    max_tier = max(by_tier.keys(), default=0)
    height = max_tier * TIER_HEIGHT + TOP_MARGIN + 90

    positions: dict[str, tuple[float, float]] = {}
    node_meta: dict[str, dict] = {}

    svg_parts = [
        f'<svg id="asset-graph" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<defs>'
        '<filter id="nodeShadow" x="-50%" y="-50%" width="200%" height="200%">'
        '<feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#14213d" flood-opacity="0.25"/>'
        '</filter>'
        '</defs>',
    ]

    # trust boundary line under tier 0 (internet-facing) if present
    if 0 in by_tier:
        boundary_y = TOP_MARGIN + 55
        svg_parts.append(
            f'<line x1="0" y1="{boundary_y}" x2="{width}" y2="{boundary_y}" stroke="#3d5580" stroke-width="1.5" '
            f'stroke-dasharray="6,5" opacity="0.45" />'
        )
        svg_parts.append(
            f'<text x="10" y="{boundary_y - 8}" font-size="9.5" font-weight="600" letter-spacing="0.5" '
            f'fill="#3d5580" font-family="IBM Plex Mono, monospace">TRUST BOUNDARY</text>'
        )
        svg_parts.append(
            f'<text x="{width - 10}" y="{boundary_y - 8}" text-anchor="end" font-size="9.5" font-weight="600" '
            f'letter-spacing="0.5" fill="#3d5580" font-family="IBM Plex Mono, monospace">TRUST BOUNDARY</text>'
        )

    for tier, items in by_tier.items():
        y = tier * TIER_HEIGHT + TOP_MARGIN
        n = len(items)
        slot = width / (n + 1)
        for i, a in enumerate(items):
            x = (i + 1) * slot
            positions[a["id"]] = (x, y)

    # curved edges, drawn under nodes
    edge_parts = []
    for a in assets:
        if a["id"] not in positions:
            continue
        x1, y1 = positions[a["id"]]
        for target_id in a.get("connections") or []:
            if target_id in positions:
                x2, y2 = positions[target_id]
                mid_x, mid_y = (x1 + x2) / 2, (y1 + y2) / 2 - 18
                edge_parts.append(
                    f'<path d="M {x1:.1f},{y1:.1f} Q {mid_x:.1f},{mid_y:.1f} {x2:.1f},{y2:.1f}" '
                    f'fill="none" stroke="#c3d3ec" stroke-width="1.4" />'
                )
    svg_parts.extend(edge_parts)

    # nodes
    for a in assets:
        if a["id"] not in positions:
            continue
        x, y = positions[a["id"]]
        color = TYPE_COLORS.get(a["type"], "#94a3b8")
        initials = _safe(_initials(a["name"]))
        node_meta[a["id"]] = a
        prominent = a.get("criticality") in ("Critical", "High")

        if prominent:
            circle = f'<circle r="{NODE_RADIUS}" fill="{color}" filter="url(#nodeShadow)" />'
            text_color = "white"
        else:
            circle = f'<circle r="{NODE_RADIUS}" fill="white" stroke="{color}" stroke-width="2.5" filter="url(#nodeShadow)" />'
            text_color = color

        svg_parts.append(
            f'<g class="asset-node" data-asset-id="{_safe(a["id"])}" style="cursor:pointer" '
            f'transform="translate({x:.1f},{y:.1f})">'
            f"{circle}"
            f'<text text-anchor="middle" dy="4" fill="{text_color}" font-size="11" font-weight="700" '
            f'font-family="IBM Plex Mono, monospace">{initials}</text>'
            f'<text text-anchor="middle" y="{NODE_RADIUS + 18}" font-size="11.5" fill="#14213d" '
            f'font-weight="600" font-family="IBM Plex Sans, sans-serif">{_safe(_truncate(a["name"]))}</text>'
            f'<text text-anchor="middle" y="{NODE_RADIUS + 31}" font-size="10" fill="#3d5580">{_safe(a["type"])}</text>'
            f"</g>"
        )

    svg_parts.append("</svg>")
    return "".join(svg_parts), _json_for_script(node_meta), (1 if 0 in by_tier else 0)
