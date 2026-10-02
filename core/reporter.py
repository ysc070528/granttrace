# -*- coding: utf-8 -*-
"""Offline HTML report generation with explicit coverage and error states."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class SecurityReportGenerator:
    VERDICT_COLORS = {
        "CONFIRMED": "#dc2626",
        "SECURE": "#059669",
        "PUBLIC": "#0284c7",
        "SUSPICIOUS": "#d97706",
        "INCONCLUSIVE": "#7c3aed",
        "SKIPPED": "#64748b",
        "ERROR": "#b91c1c",
    }

    @staticmethod
    def _escape(value: Any) -> str:
        return html.escape(str(value), quote=True)

    @classmethod
    def _json_pre(cls, value: Any) -> str:
        rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        return cls._escape(rendered)

    @classmethod
    def generate(
        cls,
        stats: Dict[str, Any],
        findings: List[Dict[str, Any]],
        target_url: str,
        output_path: str = "API_Security_Report.html",
        results: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        results = results or []
        generated_at = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

        cards = [
            ("规范端点", stats.get("total_endpoints", 0), "#0f172a"),
            ("确认漏洞", stats.get("confirmed", len(findings)), "#dc2626"),
            ("扫描错误", stats.get("error_count", 0), "#b91c1c"),
            ("结论不确定", stats.get("inconclusive_count", 0), "#7c3aed"),
            ("尝试覆盖率", f"{stats.get('coverage_pct', 0.0):.1f}%", "#0284c7"),
            ("确定性覆盖率", f"{stats.get('conclusive_coverage_pct', 0.0):.1f}%", "#059669"),
        ]
        cards_html = "".join(
            f"""
            <div class="card">
              <div class="label">{cls._escape(label)}</div>
              <div class="value" style="color:{color}">{cls._escape(value)}</div>
            </div>
            """
            for label, value, color in cards
        )

        warnings: List[str] = []
        if stats.get("error_count", 0):
            warnings.append("扫描中存在错误；不能把未完成的检查解释为安全。")
        if stats.get("inconclusive_count", 0):
            warnings.append("部分检查证据不足，需要补充有效资源、身份或读回配置。")
        if stats.get("skipped_count", 0):
            warnings.append("部分检查被跳过；默认模式不会执行状态变更测试。")
        if stats.get("suspicious_count", 0):
            warnings.append("存在可疑结果，尚未确认或排除风险，需要人工复核。")
        if not stats.get("conclusive_count", 0):
            warnings.append("本次没有形成任何确定性检查结论，不能视为安全通过。")
        warning_html = ""
        if warnings:
            warning_html = "<div class='notice'><strong>范围提示</strong><ul>" + "".join(
                f"<li>{cls._escape(item)}</li>" for item in warnings
            ) + "</ul></div>"

        result_rows = []
        for item in results:
            verdict = str(item.get("verdict", "INCONCLUSIVE")).upper()
            color = cls.VERDICT_COLORS.get(verdict, "#64748b")
            result_rows.append(
                "<tr>"
                f"<td><span class='pill' style='background:{color}'>{cls._escape(verdict)}</span></td>"
                f"<td>{cls._escape(item.get('check', ''))}</td>"
                f"<td><code>{cls._escape(item.get('endpoint', ''))}</code></td>"
                f"<td>{cls._escape(item.get('reason', ''))}</td>"
                "</tr>"
            )
        results_html = "".join(result_rows) or (
            "<tr><td colspan='4'>没有端点级结果；本报告不能用于安全结论。</td></tr>"
        )

        finding_html_parts: List[str] = []
        for index, finding in enumerate(findings, 1):
            severity = str(finding.get("severity", "High"))
            evidence = finding.get("evidence", {})
            finding_html_parts.append(
                f"""
                <article class="finding">
                  <div class="finding-head">
                    <div>
                      <span class="index">#{index} · {cls._escape(finding.get('cwe', 'CWE-Unknown'))}</span>
                      <h3>{cls._escape(finding.get('type', 'Finding'))}</h3>
                      <code>{cls._escape(finding.get('endpoint', ''))}</code>
                    </div>
                    <span class="severity">{cls._escape(severity)}</span>
                  </div>
                  <p>{cls._escape(finding.get('details', ''))}</p>
                  <details>
                    <summary>查看已最小化的证据</summary>
                    <pre>{cls._json_pre(evidence)}</pre>
                  </details>
                </article>
                """
            )
        findings_html = "".join(finding_html_parts)
        if not findings_html:
            findings_html = (
                "<div class='empty'>本次没有确认漏洞。请结合覆盖率、错误和不确定项判断结果。</div>"
            )

        document = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>API-Sentinel 审计报告</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, "Segoe UI", Arial, sans-serif; }}
    body {{ margin:0; background:#f8fafc; color:#0f172a; }}
    main {{ max-width:1180px; margin:0 auto; padding:32px 20px 56px; }}
    header {{ display:flex; justify-content:space-between; gap:24px; align-items:flex-start;
              border-bottom:1px solid #cbd5e1; padding-bottom:20px; }}
    h1 {{ margin:0 0 8px; font-size:28px; }} h2 {{ margin-top:32px; }} h3 {{ margin:8px 0; }}
    .meta {{ color:#475569; font-size:14px; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin:24px 0; }}
    .card,.finding,.empty,.notice {{ background:white; border:1px solid #e2e8f0; border-radius:12px;
                                   padding:18px; box-shadow:0 1px 3px rgba(15,23,42,.06); }}
    .label {{ color:#64748b; font-size:12px; font-weight:700; text-transform:uppercase; }}
    .value {{ margin-top:7px; font-size:27px; font-weight:800; }}
    .notice {{ border-left:5px solid #d97706; background:#fffbeb; }}
    table {{ width:100%; border-collapse:collapse; background:white; border:1px solid #e2e8f0; }}
    th,td {{ padding:11px; border-bottom:1px solid #e2e8f0; text-align:left; vertical-align:top; font-size:13px; }}
    th {{ background:#f1f5f9; }} .pill,.severity {{ color:white; padding:4px 9px; border-radius:999px;
                                                  font-size:11px; font-weight:800; }}
    .severity {{ background:#dc2626; }} .finding {{ margin-bottom:16px; border-left:5px solid #dc2626; }}
    .finding-head {{ display:flex; justify-content:space-between; gap:20px; }}
    .index {{ color:#64748b; font-size:12px; }} code {{ color:#0369a1; overflow-wrap:anywhere; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#0f172a; color:#e2e8f0;
           padding:14px; border-radius:8px; max-height:360px; overflow:auto; }}
    summary {{ cursor:pointer; color:#334155; font-weight:700; }}
  </style>
</head>
<body><main>
  <header>
    <div><h1>API-Sentinel 审计报告</h1>
      <div class="meta">目标：<strong>{cls._escape(target_url)}</strong></div>
      <div class="meta">生成时间：{cls._escape(generated_at)}</div>
    </div>
    <span class="pill" style="background:#334155">v2.3.1-final</span>
  </header>
  <section class="grid">{cards_html}</section>
  {warning_html}
  <h2>端点结果</h2>
  <div style="overflow:auto"><table>
    <thead><tr><th>结论</th><th>检查</th><th>端点</th><th>依据</th></tr></thead>
    <tbody>{results_html}</tbody>
  </table></div>
  <h2>确认的漏洞</h2>
  {findings_html}
</main></body></html>"""

        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(document)

