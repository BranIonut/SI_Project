from collections import defaultdict
from dataclasses import dataclass
from html import escape
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Model.models import Performance, app


OUTPUT_DIR = Path(__file__).resolve().parent


@dataclass
class PerformanceRow:
    framework: str
    algorithm: str
    operation_type: str
    execution_time_ms: float
    memory_usage_mb: float
    throughput_mib_per_second: float | None


def load_performance_rows():
    with app.app_context():
        performances = Performance.query.order_by(Performance.created_at.asc()).all()
        rows = []
        for performance in performances:
            operation = performance.operation
            if operation is None:
                continue

            rows.append(
                PerformanceRow(
                    framework=operation.framework.display_name
                    or operation.framework.name
                    if operation.framework
                    else "Unknown framework",
                    algorithm=operation.algorithm.name if operation.algorithm else "Unknown algorithm",
                    operation_type=operation.operation_type,
                    execution_time_ms=performance.execution_time_ms,
                    memory_usage_mb=performance.memory_usage_mb,
                    throughput_mib_per_second=performance.throughput_mib_per_second,
                )
            )
        return rows


def average_by(rows, key_fn, value_fn):
    grouped = defaultdict(list)
    for row in rows:
        value = value_fn(row)
        if value is not None:
            grouped[key_fn(row)].append(value)

    return sorted(
        ((key, sum(values) / len(values), len(values)) for key, values in grouped.items()),
        key=lambda item: item[1],
        reverse=True,
    )


def write_bar_chart(path, title, subtitle, items, unit, lower_is_better=False):
    width = 720
    row_height = 34
    top = 58
    left = 190
    right = 110
    bottom = 28
    height = max(150, top + len(items) * row_height + bottom)
    chart_width = width - left - right
    max_value = max((value for _, value, _ in items), default=1.0)
    bar_color = "#2563eb" if not lower_is_better else "#16a34a"

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        f'<text x="20" y="34" font-family="Segoe UI, Arial, sans-serif" font-size="20" font-weight="700" fill="#111827">{escape(title)}</text>',
    ]

    if not items:
        lines.append(
            '<text x="20" y="88" font-family="Segoe UI, Arial, sans-serif" font-size="14" fill="#6b7280">Nu exista date.</text>'
        )
    else:
        for index, (label, value, count) in enumerate(items):
            y = top + index * row_height
            bar_width = 0 if max_value == 0 else (value / max_value) * chart_width
            value_text = f"{value:.2f} {unit}"
            lines.extend(
                [
                    f'<text x="20" y="{y + 18}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#374151">{escape(label)}</text>',
                    f'<rect x="{left}" y="{y + 4}" width="{bar_width:.1f}" height="16" rx="2" fill="{bar_color}"/>',
                    f'<text x="{left + chart_width + 12}" y="{y + 18}" font-family="Segoe UI, Arial, sans-serif" font-size="12" fill="#374151">{escape(value_text)}</text>',
                ]
            )

    lines.append("</svg>")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html_report(path, charts):
    chart_markup = "\n".join(
        f'<section><img src="{escape(filename)}" alt="{escape(title)}"></section>'
        for title, filename in charts
    )
    html = f"""<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <title>Diagrame performanta criptografica</title>
  <style>
    body {{
      margin: 0;
      background: #ffffff;
      color: #111827;
      font-family: "Segoe UI", Arial, sans-serif;
    }}
    main {{
      max-width: 760px;
      margin: 0 auto;
      padding: 24px;
    }}
    h1 {{
      margin: 0 0 6px;
      font-size: 24px;
    }}
    p {{
      margin: 0 0 18px;
      color: #4b5563;
    }}
    section {{
      margin-top: 18px;
    }}
    img {{
      width: 100%;
      height: auto;
      display: block;
      border: 1px solid #e5e7eb;
      background: #ffffff;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Diagrame performanta criptografica</h1>
    <p>Media valorilor salvate in baza locala.</p>
    {chart_markup}
  </main>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")


def main():
    rows = load_performance_rows()

    execution_by_framework = average_by(
        rows,
        key_fn=lambda row: row.framework,
        value_fn=lambda row: row.execution_time_ms,
    )
    throughput_by_framework = average_by(
        rows,
        key_fn=lambda row: row.framework,
        value_fn=lambda row: row.throughput_mib_per_second,
    )
    execution_by_algorithm = average_by(
        rows,
        key_fn=lambda row: row.algorithm,
        value_fn=lambda row: row.execution_time_ms,
    )
    memory_by_framework = average_by(
        rows,
        key_fn=lambda row: row.framework,
        value_fn=lambda row: row.memory_usage_mb,
    )

    charts = [
        (
            "Timp mediu pe framework",
            "performance_by_framework.svg",
            "Media execution_time_ms pentru fiecare framework.",
            execution_by_framework,
            "ms",
            True,
        ),
        (
            "Throughput mediu pe framework",
            "throughput_by_framework.svg",
            "Media throughput_mib_per_second pentru fiecare framework.",
            throughput_by_framework,
            "MiB/s",
            False,
        ),
        (
            "Timp mediu pe algoritm",
            "performance_by_algorithm.svg",
            "Media execution_time_ms pentru fiecare algoritm.",
            execution_by_algorithm,
            "ms",
            True,
        ),
        (
            "Memorie medie pe framework",
            "memory_by_framework.svg",
            "Media memory_usage_mb pentru fiecare framework.",
            memory_by_framework,
            "MB",
            True,
        ),
    ]

    for title, filename, subtitle, items, unit, lower_is_better in charts:
        write_bar_chart(OUTPUT_DIR / filename, title, subtitle, items, unit, lower_is_better)

    write_html_report(
        OUTPUT_DIR / "performance_report.html",
        [(title, filename) for title, filename, *_ in charts],
    )

    print(f"Generated {len(charts)} SVG charts and performance_report.html in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
