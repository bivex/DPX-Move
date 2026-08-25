"""SOLID principles and Move code quality smell rules."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import CodeModel
from pattern_detector.domain.detection import Detection
from pattern_detector.domain.rules.base import BaseRule
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
)


class MonolithicModuleSrpRule(BaseRule):
    """Detects monolithic Move modules declaring excessive structs (>= 8) or functions (>= 15)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for m in model.all_modules:
            if len(m.structs) >= 8 or len(m.functions) >= 15:
                evidences = [
                    Evidence(
                        rule_code="SRP_MONOLITHIC_MODULE",
                        description=f"Module '{m.name}' declares {len(m.structs)} structs and {len(m.functions)} functions; decompose into cohesive sub-modules using friend visibility",
                        weight=0.88,
                        location=m.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MONOLITHIC_MODULE_SRP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=m.name,
                        target_kind="module",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=m.location,
                        evidences=evidences,
                    )
                )
        return detections


class FatResourceInterfaceIspRule(BaseRule):
    """Detects fat resource structs declaring excessive fields (>= 10), violating Interface Segregation."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if len(s.fields) >= 10:
                evidences = [
                    Evidence(
                        rule_code="ISP_FAT_RESOURCE",
                        description=f"Struct '{s.name}' declares {len(s.fields)} fields; consider decomposing into smaller composable dynamic fields",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FAT_RESOURCE_INTERFACE_ISP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class HardcodedAddressOcpRule(BaseRule):
    """Detects hardcoding literal hex addresses (@0x...) instead of named package addresses."""

    HEX_ADDR_PATTERN = re.compile(r"@[0-9a-fA-Fx]{6,}\b")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            matches = self.HEX_ADDR_PATTERN.findall(fn.body)
            if matches:
                evidences = [
                    Evidence(
                        rule_code="OCP_HARDCODED_ADDRESS",
                        description=f"Function '{fn.name}' hardcodes literal hex address '{matches[0]}'; use named package addresses in Move.toml",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.HARDCODED_ADDRESS_OCP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
