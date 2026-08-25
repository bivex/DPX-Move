"""Move Smart Contract Security & Hazard detection rules."""

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


class UnprotectedResourceMutationHazardRule(BaseRule):
    """Detects public entry functions taking &mut Resource without capability or signer authorization."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if (fn.is_entry or fn.visibility == "public") and any("&mut " in p for p in fn.parameters):
                has_signer = any("&signer" in p for p in fn.parameters)
                has_cap = any("Cap" in p or "Capability" in p for p in fn.parameters)
                if not has_signer and not has_cap and not fn.has_assert:
                    evidences = [
                        Evidence(
                            rule_code="HAZARD_UNPROTECTED_MUTATION",
                            description=f"Public entry function '{fn.name}' takes mutable references without capability or signer authorization check",
                            weight=0.92,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.UNPROTECTED_RESOURCE_MUTATION_HAZARD,
                            pattern_category=PatternCategory.MOVE_SECURITY_HAZARDS,
                            target_name=fn.name,
                            target_kind="fn",
                            confidence=Confidence(score=0.92, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class ArbitraryCoinDrainHazardRule(BaseRule):
    """Detects public functions transferring or minting coins without signer verification."""

    TRANSFER_PATTERN = re.compile(r"\b(coin::transfer|transfer::public_transfer|transfer::transfer)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if (fn.is_entry or fn.visibility == "public") and self.TRANSFER_PATTERN.search(fn.body):
                has_signer = any("&signer" in p for p in fn.parameters)
                has_cap = any("Cap" in p or "Capability" in p for p in fn.parameters)
                if not has_signer and not has_cap and not fn.has_assert:
                    evidences = [
                        Evidence(
                            rule_code="HAZARD_ARBITRARY_COIN_DRAIN",
                            description=f"Public function '{fn.name}' executes asset transfer without signer or capability authorization check",
                            weight=0.92,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.ARBITRARY_COIN_DRAIN_HAZARD,
                            pattern_category=PatternCategory.MOVE_SECURITY_HAZARDS,
                            target_name=fn.name,
                            target_kind="fn",
                            confidence=Confidence(score=0.92, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class MissingAbortAssertionHazardRule(BaseRule):
    """Detects state updates in branching logic without assert! verification."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "if (" in fn.body and not fn.has_assert and "abort " not in fn.body and ("borrow_global_mut" in fn.body or "move_to" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="HAZARD_MISSING_ABORT_ASSERT",
                        description=f"Function '{fn.name}' mutates global state across branches without assert! or explicit abort verification",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MISSING_ABORT_ASSERTION_HAZARD,
                        pattern_category=PatternCategory.MOVE_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class VectorOverflowDosHazardRule(BaseRule):
    """Detects unbounded loop over dynamic vector risking transaction gas limit exhaustion."""

    LOOP_PATTERN = re.compile(r"\b(while|loop)\s*\(?.*?\)?\s*\{[\s\S]*?\bvector::length\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.LOOP_PATTERN.search(fn.body) and not fn.has_assert:
                evidences = [
                    Evidence(
                        rule_code="HAZARD_VECTOR_OVERFLOW_DOS",
                        description=f"Function '{fn.name}' loops over dynamic vector length without bounds check, risking Transaction Gas Limit Denial of Service",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.VECTOR_OVERFLOW_DOS_HAZARD,
                        pattern_category=PatternCategory.MOVE_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
