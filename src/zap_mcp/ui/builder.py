"""Utility helpers for constructing MCP-UI resources."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from mcp_ui_server import create_ui_resource


@dataclass(slots=True)
class UIBuilder:
    """Render HTML or Remote DOM payloads for MCP clients."""

    template_dir: Optional[Path] = None

    def _wrap_html(self, uri: str, html: str) -> Dict[str, Any]:
        return create_ui_resource(
            uri=uri,
            content={"type": "raw_html", "htmlString": html},
            encoding="text",
        )

    async def create_security_dashboard(
        self,
        alerts: Dict[str, int],
        scan_status: Dict[str, Any],
    ) -> Dict[str, Any]:
        html = """
        <section class="zap-dashboard">
            <h2>ZAP Scan Summary</h2>
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Scan Type:</strong> {scan_type}</p>
            <div class="zap-alerts">{alerts}</div>
        </section>
        """.format(
            target=scan_status.get("url", "unknown"),
            scan_type=scan_status.get("type", "unknown"),
            alerts=", ".join(f"{k}: {v}" for k, v in alerts.items()),
        )
        return self._wrap_html("ui://zap/dashboard", html)

    async def create_vulnerability_viewer(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(vulnerability)
        return create_ui_resource(
            uri=f"ui://zap/vuln/{vulnerability.get('id', 'unknown')}",
            content={"type": "remote_dom", "script": f"renderVulnerability({payload});", "framework": "react"},
            encoding="text",
        )

    async def create_assessment_dashboard(
        self,
        target_url: str,
        assessment_type: str,
        steps: Iterable[Dict[str, Any]],
        alerts: Dict[str, int],
    ) -> Dict[str, Any]:
        payload = {
            "target": target_url,
            "assessmentType": assessment_type,
            "steps": list(steps),
            "alerts": alerts,
        }
        return create_ui_resource(
            uri="ui://zap/assessment",
            content={
                "type": "remote_dom",
                "script": f"renderAssessment({json.dumps(payload)});",
                "framework": "react",
            },
            encoding="text",
        )
