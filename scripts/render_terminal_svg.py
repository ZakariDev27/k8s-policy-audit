#!/usr/bin/env python3
"""Render a kpaudit text report as a terminal-style SVG for the README.

    kpaudit scan demo/insecure --min-severity high --fail-on never \\
      | python3 scripts/render_terminal_svg.py "kpaudit scan demo/insecure --min-severity high" \\
      > docs/images/scan-insecure.svg
"""

from __future__ import annotations

import sys
from xml.sax.saxutils import escape

SEVERITY_COLORS = {
    "CRITICAL": "#ff7ae0",
    "HIGH": "#ff6b6b",
    "MEDIUM": "#f2c14e",
    "LOW": "#5ccfe6",
    "INFO": "#8b949e",
}
TEXT, DIM, HEADING, BACKGROUND, BAR = "#d7dce2", "#8b949e", "#ffffff", "#0d1117", "#161b22"
CHAR_WIDTH, LINE_HEIGHT, PADDING, BAR_HEIGHT = 8.4, 19, 18, 34


def render_line(line: str, y: float) -> str:
    x = PADDING
    first = line.split(" ", 1)[0]
    if first in SEVERITY_COLORS:
        rest = escape(line[len(first):])
        return (
            f'<text x="{x}" y="{y}" xml:space="preserve">'
            f'<tspan fill="{SEVERITY_COLORS[first]}" font-weight="bold">{first}</tspan>'
            f'<tspan fill="{HEADING}">{rest}</tspan></text>'
        )
    stripped = line.strip()
    if line.startswith("$ "):
        fill, weight = HEADING, "bold"
    elif stripped.startswith("Fix:") or line.startswith("         ") or line.startswith("kpaudit "):
        fill, weight = DIM, "normal"
    elif line and not line.startswith(" "):
        fill, weight = HEADING, "bold"
    else:
        fill, weight = TEXT, "normal"
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-weight="{weight}" '
        f'xml:space="preserve">{escape(line)}</text>'
    )


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else "kpaudit scan"
    lines = ["$ " + command] + sys.stdin.read().rstrip("\n").split("\n")
    width = int(max(len(line) for line in lines) * CHAR_WIDTH + PADDING * 2)
    height = int(BAR_HEIGHT + PADDING + len(lines) * LINE_HEIGHT + PADDING / 2)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="{escape(command)} output">',
        f'<rect width="{width}" height="{height}" rx="8" fill="{BACKGROUND}"/>',
        f'<path d="M0 8a8 8 0 0 1 8-8h{width - 16}a8 8 0 0 1 8 8v{BAR_HEIGHT - 8}H0z" '
        f'fill="{BAR}"/>',
        '<circle cx="20" cy="17" r="6" fill="#ff5f56"/>',
        '<circle cx="40" cy="17" r="6" fill="#ffbd2e"/>',
        '<circle cx="60" cy="17" r="6" fill="#27c93f"/>',
        '<g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, \'Liberation Mono\', '
        'monospace" font-size="14">',
    ]
    y = BAR_HEIGHT + PADDING + 4
    for line in lines:
        parts.append(render_line(line, y))
        y += LINE_HEIGHT
    parts += ["</g>", "</svg>"]
    sys.stdout.write("\n".join(parts) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
