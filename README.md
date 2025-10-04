# ZAP MCP Server

This repository contains an experimental [FastMCP](https://gofastmcp.com) server that exposes
OWASP ZAP scanning workflows. It provides a set of tools, resources, and prompts that can be used
by MCP compatible clients to orchestrate spidering, active scanning, and reporting tasks while
surfacing rich UI artefacts via MCP-UI.

## Features

- Async wrapper around the official `python-owasp-zap-v2.4` client
- Tools for spidering, scanning, retrieving alerts, and generating reports
- Resources that expose live status and summaries of findings
- Prompts for guided assessments and API-centric testing

## Development

```bash
uv pip install -e .[dev]
pytest
```

Ensure a ZAP daemon is available locally before invoking integration tests. The easiest way is to
launch the official Docker image:

```bash
docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080
```
