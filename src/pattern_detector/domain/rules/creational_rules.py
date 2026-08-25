"""GoF Creational design pattern detection rules for Move (5/5)."""

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


class SingletonCapabilityVaultRule(BaseRule):
    """Detects Singleton pattern via non-copyable unique capability structs (AdminCap / MasterCap)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if s.is_capability and "copy" not in s.abilities:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_SINGLETON_CAPABILITY",
                        description=f"Struct '{s.name}' implements Singleton Capability pattern (non-copyable 'has {', '.join(sorted(s.abilities))}')",
                        weight=0.92,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.SINGLETON_CAPABILITY_VAULT,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class FactoryResourceMintConstructorRule(BaseRule):
    """Detects Factory pattern packing and constructing new resource instances."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("mint", "create", "new", "create_vault", "spawn_object") or fn.name.startswith("create_") or fn.name.startswith("mint_"):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_FACTORY_CONSTRUCTOR",
                        description=f"Function '{fn.name}' implements Factory Resource Constructor initializing and packing resource structs",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACTORY_RESOURCE_MINT_CONSTRUCTOR,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class AbstractFactoryPoolCreatorRule(BaseRule):
    """Detects Abstract Factory creating generic liquidity pools and market vaults parameterized by coin types."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if len(fn.type_parameters) >= 2 and ("pool" in fn.name.lower() or "pair" in fn.name.lower() or "vault" in fn.name.lower()):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_ABSTRACT_FACTORY_POOL",
                        description=f"Generic function '{fn.name}<{', '.join(fn.type_parameters)}>' implements Abstract Factory creating parameterized multi-asset pools",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ABSTRACT_FACTORY_POOL_CREATOR,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class BuilderMultisigProposalRule(BaseRule):
    """Detects Builder pattern incrementally constructing multi-step proposals."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Builder" in s.name or "Proposal" in s.name or "Batch" in s.name:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_BUILDER_PROPOSAL",
                        description=f"Struct '{s.name}' implements Builder pattern assembling multi-step governance action proposals",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BUILDER_MULTISIG_PROPOSAL,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class PrototypeResourceCloneSplitRule(BaseRule):
    """Detects Prototype pattern splitting and merging coin balance resources."""

    SPLIT_PATTERN = re.compile(r"\b(coin::split|balance::split|coin::join|balance::join|coin::extract)\b")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.SPLIT_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_PROTOTYPE_SPLIT",
                        description=f"Function '{fn.name}' implements Prototype pattern splitting and recombining linear coin balances",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PROTOTYPE_RESOURCE_CLONE_SPLIT,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
