"""FastMCP server wiring together all ZAP integrations."""

from __future__ import annotations

import logging
from typing import Optional

from fastmcp import FastMCP
from fastmcp.server import ServerSettings

from .config import get_settings
from .core.zap_client import ZAPClient
from .prompts.api_testing import APITestingPrompt
from .prompts.assessment import SecurityAssessmentPrompt
from .prompts.owasp import OWASPCompliancePrompt
from .resources.compliance import ComplianceStatusResource
from .resources.findings import VulnerabilityDetailsResource
from .resources.status import AlertSummaryResource, ScanStatusResource
from .tools.alerts import GetAlertsTool, MarkFalsePositiveTool
from .tools.reporting import GenerateReportTool
from .tools.scanning import ActiveScanTool, ScanUrlTool, SpiderTool
from .ui.builder import UIBuilder


settings = get_settings()
logging.basicConfig(level=getattr(logging, settings.server.log_level))
logger = logging.getLogger(__name__)

mcp = FastMCP(
    name=settings.server.name,
    version=settings.server.version,
    settings=ServerSettings(host=settings.server.host, port=settings.server.port),
)

_zap_client: Optional[ZAPClient] = None
_ui_builder: Optional[UIBuilder] = None


@mcp.on_startup
async def _startup() -> None:
    global _zap_client
    global _ui_builder

    logger.info("starting %s", settings.server.name)
    _zap_client = ZAPClient()
    try:
        await _zap_client.connect()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to connect to ZAP: %%s", exc)

    _ui_builder = UIBuilder() if settings.server.enable_ui else None

    mcp.add_tool(ScanUrlTool(_zap_client, _ui_builder))
    mcp.add_tool(ActiveScanTool(_zap_client))
    mcp.add_tool(SpiderTool(_zap_client))
    mcp.add_tool(GetAlertsTool(_zap_client))
    mcp.add_tool(GenerateReportTool(_zap_client))
    if settings.features.compliance_checks:
        mcp.add_tool(MarkFalsePositiveTool(_zap_client))

    mcp.add_resource(ScanStatusResource(_zap_client))
    mcp.add_resource(AlertSummaryResource(_zap_client))
    mcp.add_resource(VulnerabilityDetailsResource(_zap_client))
    if settings.features.compliance_checks:
        mcp.add_resource(ComplianceStatusResource(_zap_client))

    mcp.add_prompt(SecurityAssessmentPrompt(_zap_client, _ui_builder))
    mcp.add_prompt(APITestingPrompt(_zap_client))
    if settings.features.compliance_checks:
        mcp.add_prompt(OWASPCompliancePrompt(_zap_client, _ui_builder))


@mcp.on_shutdown
async def _shutdown() -> None:
    global _zap_client
    if _zap_client:
        await _zap_client.close()


def main() -> None:
    logger.info("MCP server listening on %s:%s", settings.server.host, settings.server.port)
    mcp.run(transport="sse", host=settings.server.host, port=settings.server.port)


if __name__ == "__main__":
    main()
