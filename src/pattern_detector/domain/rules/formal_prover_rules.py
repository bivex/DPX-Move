"""Move Prover Formal Verification and Specification rules."""

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


class MoveProverFormalSpecRule(BaseRule):
    """Detects formal Move Prover mathematical specifications (spec module, spec fun, ensures, aborts_if)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for spec in model.all_specs:
            evidences = [
                Evidence(
                    rule_code="PROVER_FORMAL_SPEC",
                    description=f"Move Prover specification block '{spec.target_name}' proves formal mathematical guarantees ({len(spec.ensures)} ensures, {len(spec.aborts_if)} aborts_if, {len(spec.invariants)} invariant)",
                    weight=0.98,
                    location=spec.location,
                )
            ]
            detections.append(
                Detection(
                    pattern_type=PatternType.MOVE_PROVER_FORMAL_SPEC,
                    pattern_category=PatternCategory.FORMAL_SPEC_PROVER,
                    target_name=spec.target_name,
                    target_kind="spec",
                    confidence=Confidence(score=0.98, evidences=evidences),
                    primary_location=spec.location,
                    evidences=evidences,
                )
            )
        return detections


class AbortCodeDomainEnumsRule(BaseRule):
    """Detects typed abort error constants (const E_...: u64 = ...)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for m in model.all_modules:
            err_consts = [c for c in m.constants if c.is_error_code]
            if err_consts:
                evidences = [
                    Evidence(
                        rule_code="MOVE_TYPED_ABORT_CODES",
                        description=f"Module '{m.name}' declares {len(err_consts)} typed abort error constant(s) for domain error handling",
                        weight=0.95,
                        location=m.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ABORT_CODE_DOMAIN_ENUMS,
                        pattern_category=PatternCategory.FORMAL_SPEC_PROVER,
                        target_name=m.name,
                        target_kind="module",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=m.location,
                        evidences=evidences,
                    )
                )
        return detections


class InvariantStateAssertionRule(BaseRule):
    """Detects explicit assert! invariant verification guards in functions."""

    ASSERT_PATTERN = re.compile(r"\bassert!\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_assert or self.ASSERT_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="MOVE_INVARIANT_ASSERTION",
                        description=f"Function '{fn.name}' enforces invariant state conditions with assert! validation",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.INVARIANT_STATE_ASSERTION,
                        pattern_category=PatternCategory.FORMAL_SPEC_PROVER,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
