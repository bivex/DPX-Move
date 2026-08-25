"""Move Idiomatic, Linear Types & Ability Composition rules."""

from __future__ import annotations

from pattern_detector.domain.code_model import CodeModel
from pattern_detector.domain.detection import Detection
from pattern_detector.domain.rules.base import BaseRule
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
)


class ResourceLinearTypeSafetyRule(BaseRule):
    """Detects linear resource types (has key, no drop/copy) enforcing Move VM balance guarantees."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if s.is_resource:
                evidences = [
                    Evidence(
                        rule_code="MOVE_LINEAR_RESOURCE_SAFETY",
                        description=f"Struct '{s.name}' is a Linear Resource ('has {', '.join(sorted(s.abilities))}'), eliminating double-spend and implicit destruction",
                        weight=0.95,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.RESOURCE_LINEAR_TYPE_SAFETY,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=s.name,
                        target_kind="resource",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class StructAbilityCompositionRule(BaseRule):
    """Detects explicit Move ability compositions (key, store, copy, drop)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if len(s.abilities) >= 2:
                evidences = [
                    Evidence(
                        rule_code="MOVE_ABILITY_COMPOSITION",
                        description=f"Struct '{s.name}' explicitly composes {len(s.abilities)} abilities ('has {', '.join(sorted(s.abilities))}') for Move VM lifecycle control",
                        weight=0.92,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STRUCT_ABILITY_COMPOSITION,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class WitnessTypeAuthorizationRule(BaseRule):
    """Detects One-Time Witness (OTW) pattern consuming single-use drop structs during module initialization."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if s.is_witness:
                evidences = [
                    Evidence(
                        rule_code="MOVE_WITNESS_AUTHORIZATION",
                        description=f"Struct '{s.name}' implements One-Time Witness (OTW) pattern ('has drop') authorizing single-instance initialization",
                        weight=0.95,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.WITNESS_TYPE_AUTHORIZATION,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class HotPotatoTransientReceiptRule(BaseRule):
    """Detects Hot Potato structs (zero abilities) enforcing same-transaction repayment (Flashloans)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if s.is_hot_potato:
                evidences = [
                    Evidence(
                        rule_code="MOVE_HOT_POTATO_RECEIPT",
                        description=f"Struct '{s.name}' has zero abilities (Hot Potato pattern), forcing atomic same-transaction consumption (e.g. Flashloan)",
                        weight=0.98,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.HOT_POTATO_TRANSIENT_RECEIPT,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.98, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class CapabilityAccessControlRule(BaseRule):
    """Detects Capability pattern structs (*Cap / *Capability) passed for granular access control."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if s.is_capability:
                evidences = [
                    Evidence(
                        rule_code="MOVE_CAPABILITY_ACCESS_CONTROL",
                        description=f"Struct '{s.name}' implements Capability Access Control pattern ('has {', '.join(sorted(s.abilities))}') for transferable permissions",
                        weight=0.95,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CAPABILITY_ACCESS_CONTROL,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class FriendModuleVisibilityRule(BaseRule):
    """Detects friend module visibility (friend package::module or public(friend) / public(package))."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for m in model.all_modules:
            has_friend_decl = len(m.friends) > 0
            has_friend_fn = any("friend" in fn.visibility or "package" in fn.visibility for fn in m.functions)
            if has_friend_decl or has_friend_fn:
                evidences = [
                    Evidence(
                        rule_code="MOVE_FRIEND_VISIBILITY",
                        description=f"Module '{m.name}' scopes internal APIs using Friend/Package visibility ({len(m.friends)} friend declarations)",
                        weight=0.92,
                        location=m.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FRIEND_MODULE_VISIBILITY,
                        pattern_category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
                        target_name=m.name,
                        target_kind="module",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=m.location,
                        evidences=evidences,
                    )
                )
        return detections
