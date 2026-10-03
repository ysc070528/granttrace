# -*- coding: utf-8 -*-
"""Offline HTML report generation with explicit coverage and error states."""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.evidence import sanitize_url


class SecurityReportGenerator:
    VERDICT_COLORS = {
        "CONFIRMED": "#dc2626",
        "SECURE": "#059669",
        "PUBLIC": "#0284c7",
        "AUTHORIZED": "#0e7490",
        "SUSPICIOUS": "#d97706",
        "INCONCLUSIVE": "#7c3aed",
        "SKIPPED": "#64748b",
        "ERROR": "#b91c1c",
    }
    VERDICT_LABELS = {
        "CONFIRMED": "确认漏洞", "SECURE": "所测检查通过", "PUBLIC": "允许公开访问",
        "AUTHORIZED": "按策略获准访问", "SUSPICIOUS": "可疑", "INCONCLUSIVE": "证据不足", "SKIPPED": "已跳过", "ERROR": "错误",
    }

    @staticmethod
    def _escape(value: Any) -> str:
        return html.escape(str(value), quote=True)

    @classmethod
    def _json_pre(cls, value: Any) -> str:
        rendered = json.dumps(value, ensure_ascii=False, indent=2, default=str)
        return cls._escape(rendered)

    @classmethod
    def _summarize(cls, item: Dict[str, Any]) -> Dict[str, Any]:
        """Explain recorded evidence without inferring account IDs or response values.

        Finding records have no verdict field; their presence means CONFIRMED. A
        missing recovery flag is unknown, rather than a successful rollback.
        """
        evidence = item.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        verdict = str(item.get("verdict", "CONFIRMED")).upper()
        check = str(item.get("check", ""))
        target = evidence.get("target_url") or item.get("target_url")
        resource = sanitize_url(str(target)) if target else "具体请求目标未记录"
        cwe = item.get("cwe")
        if check == "BOLA" or cwe == "CWE-639":
            if target and isinstance(evidence.get("visitor_cross"), dict):
                summary = f"Visitor 身份访问配置为 Owner 的资源：{resource}。"
            else:
                summary = "检查目标：Visitor 能否访问配置为 Owner 的资源；具体请求对照未记录。"
            decision = evidence.get("decision_evidence")
            decision = decision if isinstance(decision, dict) else {}
            signal_labels = {
                "matching_resource_identifier": "双方响应的资源标识一致",
                "exact_business_value_match": "双方响应的业务值一致",
                "high_business_value_overlap": "双方响应存在较高的非公开业务值重合",
            }
            signals = decision.get("confirmation_signals")
            signals = signals if isinstance(signals, list) else []
            confirmations = [signal_labels[signal] for signal in signals
                             if isinstance(signal, str) and signal in signal_labels]
            if verdict == "CONFIRMED" and confirmations:
                verification = "已确认对象级越权：" + "；".join(confirmations) + "。"
            elif verdict == "CONFIRMED":
                verification = "报告结论为确认漏洞；响应对照摘要不足，请复核下方证据。"
            elif verdict == "PUBLIC":
                verification = "本次结果为按配置允许公开访问，请核对该资源的公开范围。"
            elif verdict == "SECURE":
                verification = "本次对照显示未授权身份的访问被拒绝；结论仅限所测身份和资源。"
            elif verdict == "AUTHORIZED":
                verification = "当前 Visitor 按配置获准读取所选 Owner 资源；仅适用于本次配置的身份与资源组合。"
            else:
                verification = "本次结论：" + cls.VERDICT_LABELS.get(verdict, verdict) + "。"
            return {
                "summary": summary, "verification": verification,
                "remediation": "服务端按当前登录身份校验资源归属、团队共享和管理员权限；未获授权时拒绝返回资源数据。",
                "retest": [
                    "在测试环境准备 Owner、Visitor 两个独立账户和各自的有效资源；先明确各身份按业务策略应被允许还是拒绝。",
                    "分别用 Owner、Visitor 和 Anonymous 读取 Owner 的同一资源，核对允许与拒绝结果及响应数据。凭据从本地安全配置加载。",
                    "同时验证 Visitor 可访问自身资源，以及合法团队共享、管理员访问按策略成功；重新扫描并比较结论。",
                ],
            }
        if check in {"MASS_ASSIGNMENT", "ROLLBACK"} or cwe == "CWE-915":
            field = evidence.get("field")
            read_field = evidence.get("readback_field")
            tested_fields = evidence.get("tested_fields")
            if not field and isinstance(tested_fields, list):
                field = ", ".join(name for name in tested_fields if isinstance(name, str))
            if field:
                summary = f"写入检查：Visitor 提交字段 {field}；测试资源：{resource}。"
                if read_field and read_field != field:
                    summary += f"独立读回字段：{read_field}。"
            else:
                summary = "写入检查：核对配置字段是否被持久保存；具体变更字段未记录。"
            after = evidence.get("after")
            readback_recorded = isinstance(after, dict) and isinstance(after.get("status"), int) and 200 <= after["status"] < 300
            if verdict == "CONFIRMED" and field and readback_recorded:
                verification = "独立读回确认该字段的测试值已持久保存。"
            elif verdict == "CONFIRMED":
                verification = "报告结论为字段持久变化；当前记录的独立读回摘要不足，请复核下方证据。"
            elif verdict == "SECURE":
                verification = "本次强一致读回未发现配置字段持久变化；结论仅限已执行的字段。"
            else:
                verification = "本次结论：" + cls.VERDICT_LABELS.get(verdict, verdict) + "。"
            rollback = evidence.get("rollback_verified")
            if rollback is True:
                verification += "原状态已通过读回核验。"
                if evidence.get("ignored_readback_paths"):
                    verification += "核验范围不含配置中忽略的易变字段。"
            elif rollback is False:
                verification += "恢复未通过核验；暂停写入测试，先人工核对并恢复该测试资源。"
            else:
                verification += "记录未提供恢复核验结果，不能据此认为原状态已恢复。"
            untested = evidence.get("untested_fields")
            if isinstance(untested, list) and untested:
                verification += f"另有 {len(untested)} 个配置字段未执行。"
            return {
                "summary": summary, "verification": verification,
                "remediation": "为当前身份明确允许更新的字段；在服务端拒绝或忽略权限、角色等未授权字段，并按业务策略校验更新权限。",
                "retest": [
                    "仅在可恢复的测试资源上复验；先保存完整原状态，确认独立读回和恢复路径可用。恢复未核验时先处理恢复问题。",
                    "用 Visitor 提交该字段的最小测试修改，再由独立读取接口核对持久状态；未授权字段应保持原值，允许更新的字段应正常工作。",
                    "恢复原状态并再次读取核验；若结果不一致或无法核验，暂停后续写入测试并人工恢复。",
                ],
            }
        return {
            "summary": "本项检查：" + str(item.get("check") or item.get("type") or "未记录检查类型") + "。",
            "verification": "本次结论：" + cls.VERDICT_LABELS.get(verdict, verdict) + "；身份、字段和恢复信息以已有证据为准。",
            "remediation": "结合接口业务策略核对已有证据；先排除配置或请求错误，再修复所确认的问题。",
            "retest": ["在测试环境使用有效身份和资源重复该检查，核对预期允许与拒绝结果；涉及写入时保存并核验原状态。"],
        }

    @classmethod
    def _guidance_html(cls, explanation: Dict[str, Any]) -> str:
        return (
            "<div class='guidance'><p><strong>修复方向：</strong>" + cls._escape(explanation["remediation"]) + "</p>"
            "<strong>安全复验步骤</strong><ol>" + "".join(
                "<li>" + cls._escape(step) + "</li>" for step in explanation["retest"]
            ) + "</ol></div>"
        )

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
        target_url = sanitize_url(target_url)
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
            explanation = cls._summarize({**item, "verdict": verdict})
            result_rows.append(
                f"<tr data-audit-item='result' data-verdict='{cls._escape(verdict)}' "
                f"data-endpoint='{cls._escape(item.get('endpoint', ''))}'>"
                f"<td><span class='pill' style='background:{color}' title='{cls._escape(cls.VERDICT_LABELS.get(verdict, verdict))}'>{cls._escape(verdict)}</span></td>"
                f"<td>{cls._escape(item.get('check', ''))}</td>"
                f"<td><code>{cls._escape(item.get('endpoint', ''))}</code></td>"
                f"<td><p class='result-summary'>{cls._escape(explanation['summary'])}</p>"
                f"<p class='result-summary'>{cls._escape(explanation['verification'])}</p>"
                f"<p class='meta'>依据：{cls._escape(item.get('reason', ''))}</p>"
                "<details><summary>修复方向、复验步骤和证据</summary>"
                f"{cls._guidance_html(explanation)}"
                f"<pre>{cls._json_pre(item.get('evidence', {}))}</pre></details></td>"
                "</tr>"
            )
        results_html = "".join(result_rows) or (
            "<tr><td colspan='4'>没有端点级结果；本报告不能用于安全结论。</td></tr>"
        )

        finding_html_parts: List[str] = []
        for index, finding in enumerate(findings, 1):
            severity = str(finding.get("severity", "High"))
            evidence = finding.get("evidence", {})
            explanation = cls._summarize({**finding, "verdict": "CONFIRMED"})
            finding_html_parts.append(
                f"""
                <article class="finding" data-audit-item="finding" data-verdict="CONFIRMED"
                         data-endpoint="{cls._escape(finding.get('endpoint', ''))}">
                  <div class="finding-head">
                    <div>
                      <span class="index">#{index} · {cls._escape(finding.get('cwe', 'CWE-Unknown'))}</span>
                      <h3>{cls._escape(finding.get('type', 'Finding'))}</h3>
                      <code>{cls._escape(finding.get('endpoint', ''))}</code>
                    </div>
                    <span class="severity">{cls._escape(severity)}</span>
                  </div>
                  <p>{cls._escape(explanation['summary'])}</p>
                  <p class="verification">{cls._escape(explanation['verification'])}</p>
                  <p class="meta">依据：{cls._escape(finding.get('details', ''))}</p>
                  {cls._guidance_html(explanation)}
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
        status_options = "".join(
            f"<option value='{verdict}'>{cls._escape(label)} · {verdict}</option>"
            for verdict, label in cls.VERDICT_LABELS.items()
        )

        document = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GrantTrace 审计报告</title>
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
    table {{ width:100%; min-width:900px; border-collapse:collapse; background:white; border:1px solid #e2e8f0; }}
    th:nth-child(3),td:nth-child(3) {{ min-width:210px; }}
    th,td {{ padding:11px; border-bottom:1px solid #e2e8f0; text-align:left; vertical-align:top; font-size:13px; }}
    th {{ background:#f1f5f9; }} .pill,.severity {{ color:white; padding:4px 9px; border-radius:999px;
                                                  font-size:11px; font-weight:800; display:inline-block;
                                                  line-height:1.4; white-space:nowrap; }}
    .severity {{ background:#dc2626; align-self:flex-start; flex-shrink:0; }}
    .finding {{ margin-bottom:16px; border-left:5px solid #dc2626; }}
    .finding-head {{ display:flex; justify-content:space-between; gap:20px; align-items:flex-start; }}
    .index {{ color:#64748b; font-size:12px; }} code {{ color:#0369a1; overflow-wrap:anywhere; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#0f172a; color:#e2e8f0;
           padding:14px; border-radius:8px; max-height:360px; overflow:auto; }}
    summary {{ cursor:pointer; color:#334155; font-weight:700; }}
    .filters {{ display:flex; flex-wrap:wrap; gap:16px; margin:24px 0 12px; }}
    .filters label {{ display:flex; flex-direction:column; gap:6px; font-size:13px; font-weight:700; }}
    input,select {{ border:1px solid #cbd5e1; border-radius:6px; padding:9px; font:inherit; background:white; }}
    input {{ min-width:240px; max-width:100%; box-sizing:border-box; }}
    .result-summary {{ margin:0 0 7px; }} .verification {{ font-weight:600; }}
    .guidance {{ margin:16px 0; font-size:14px; line-height:1.6; }}
    .guidance li {{ margin:6px 0; }} [hidden] {{ display:none !important; }}
    @media (max-width:640px) {{ main {{ padding:20px 12px; }} header {{ flex-wrap:wrap; }} }}
  </style>
</head>
<body><main>
  <header>
    <div><h1>GrantTrace 审计报告</h1>
      <div class="meta">目标：<strong>{cls._escape(target_url)}</strong></div>
      <div class="meta">生成时间：{cls._escape(generated_at)}</div>
    </div>
    <span class="pill" style="background:#334155">v2.3.1-final</span>
  </header>
  <section class="grid">{cards_html}</section>
  {warning_html}
  <div class="filters">
    <label for="endpoint-search">搜索端点
      <input id="endpoint-search" type="search" placeholder="例如 GET /users" autocomplete="off">
    </label>
    <label for="verdict-filter">按状态筛选
      <select id="verdict-filter"><option value="">全部状态</option>{status_options}</select>
    </label>
  </div>
  <noscript><p class="meta">启用浏览器 JavaScript 后可使用搜索和筛选；全部报告内容已保存在此文件中。</p></noscript>
  <p class="meta" id="filter-count" role="status" aria-live="polite">端点结果 {len(results)}/{len(results)} 条 · 确认漏洞 {len(findings)}/{len(findings)} 条</p>
  <h2>端点结果</h2>
  <div style="overflow:auto" role="region" aria-label="端点结果，可横向滚动" tabindex="0"><table>
    <thead><tr><th>结论</th><th>检查</th><th>端点</th><th>访问与变化说明</th></tr></thead>
    <tbody>{results_html}</tbody>
  </table></div>
  <p id="no-matching-results" class="empty" hidden>没有匹配的端点结果。</p>
  <h2>确认的漏洞</h2>
  {findings_html}
  <p id="no-matching-findings" class="empty" hidden>没有匹配的确认漏洞。</p>
</main>
<script>
  (() => {{
    const search = document.getElementById('endpoint-search');
    const filter = document.getElementById('verdict-filter');
    const items = Array.from(document.querySelectorAll('[data-audit-item]'));
    const totals = {{result: {len(results)}, finding: {len(findings)}}};
    function applyFilters() {{
      const query = search.value.trim().toLowerCase();
      const visible = {{result: 0, finding: 0}};
      items.forEach(item => {{
        item.hidden = !item.dataset.endpoint.toLowerCase().includes(query) ||
          Boolean(filter.value && item.dataset.verdict !== filter.value);
        if (!item.hidden) visible[item.dataset.auditItem] += 1;
      }});
      document.getElementById('filter-count').textContent =
        `端点结果 ${{visible.result}}/${{totals.result}} 条 · 确认漏洞 ${{visible.finding}}/${{totals.finding}} 条`;
      document.getElementById('no-matching-results').hidden = !totals.result || visible.result > 0;
      document.getElementById('no-matching-findings').hidden = !totals.finding || visible.finding > 0;
    }}
    search.addEventListener('input', applyFilters);
    filter.addEventListener('change', applyFilters);
    applyFilters();
  }})();
</script></body></html>"""

        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(document)

