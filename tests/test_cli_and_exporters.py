"""Unit tests for CLI commands and JSON/Markdown/SARIF/HTML/LLM exporters for Move."""

from __future__ import annotations

import json
from typer.testing import CliRunner

from pattern_detector.adapters.inbound.cli.main import app
from pattern_detector.adapters.outbound.persistence.formatters import (
    JsonReportFormatter,
    MarkdownReportFormatter,
    SarifReportFormatter,
)
from pattern_detector.adapters.outbound.persistence.html_report_formatter import HtmlReportFormatter
from pattern_detector.adapters.outbound.persistence.llm_report_formatter import LlmReportFormatter
from pattern_detector.domain.detection import Detection, DetectionReport
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
    SourceLocation,
)

runner = CliRunner()


def _dummy_report() -> DetectionReport:
    ev = Evidence(
        rule_code="MOVE_TEST",
        description="Test heuristic for Move linear resources",
        weight=0.95,
        location=SourceLocation("vault.move", 10),
    )
    det = Detection(
        pattern_type=PatternType.RESOURCE_LINEAR_TYPE_SAFETY,
        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        target_name="Vault",
        target_kind="resource",
        confidence=Confidence(score=0.95, evidences=[ev]),
        primary_location=SourceLocation("vault.move", 10),
        evidences=[ev],
    )
    return DetectionReport(
        project_path="test_project",
        scanned_files_count=1,
        detections=[det],
        elapsed_seconds=0.012,
    )


def test_cli_rules_command() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "DPX-Move" in result.stdout
    assert "Linear Resource" in result.stdout or "Resource" in result.stdout


def test_cli_info_command() -> None:
    result = runner.invoke(app, ["info", "resource_linear_type_safety"])
    assert result.exit_code == 0
    assert "Resource Linear Type Safety" in result.stdout


def test_exporters_format() -> None:
    rep = _dummy_report()

    json_out = JsonReportFormatter().format(rep)
    data = json.loads(json_out)
    assert data["total_detections_count"] == 1

    md_out = MarkdownReportFormatter().format(rep)
    assert "# 📦 DPX-Move: Move Smart Contract Architectural Pattern Report" in md_out

    sarif_out = SarifReportFormatter().format(rep)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"

    html_out = HtmlReportFormatter().format(rep)
    assert "DPX-Move Architecture & Resource Safety Observability HUD" in html_out

    llm_out = LlmReportFormatter().format_scan_report(rep)
    assert '<codebase_architecture_analysis language="move">' in llm_out
