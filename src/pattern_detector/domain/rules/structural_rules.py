"""GoF Structural design pattern detection rules for Move (7/7)."""

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


class AdapterOracleWrapperRule(BaseRule):
    """Detects Adapter pattern wrapping external price feeds into uniform quotation structs."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Oracle" in s.name or "PriceFeed" in s.name or "Adapter" in s.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_ADAPTER_ORACLE",
                        description=f"Struct '{s.name}' implements Adapter pattern standardizing external price oracles into uniform quotation interfaces",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ADAPTER_ORACLE_WRAPPER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class BridgeCrossChainPortalRule(BaseRule):
    """Detects Bridge pattern decoupling cross-chain message portals from specific relayer backends."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Bridge" in s.name or "Portal" in s.name or "Messenger" in s.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_BRIDGE_PORTAL",
                        description=f"Struct '{s.name}' implements Bridge pattern separating cross-chain payload verification from execution",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BRIDGE_CROSS_CHAIN_PORTAL,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class CompositeBundleBagRule(BaseRule):
    """Detects Composite pattern aggregating heterogeneous resource types using sui::bag or Table."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Bag" in s.name or "Bundle" in s.name or "Collection" in s.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_COMPOSITE_BAG",
                        description=f"Struct '{s.name}' implements Composite pattern aggregating heterogeneous resource types into a unified container",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMPOSITE_BUNDLE_BAG,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class DecoratorYieldVaultBoosterRule(BaseRule):
    """Detects Decorator pattern wrapping base staking deposits with reward multiplier metadata."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Boost" in s.name or "Multiplier" in s.name or "Lock" in s.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_DECORATOR_BOOSTER",
                        description=f"Struct '{s.name}' implements Decorator pattern augmenting base staking resources with reward booster metadata",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DECORATOR_YIELD_VAULT_BOOSTER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class FacadeRouterAggregatorRule(BaseRule):
    """Detects Facade DEX Router unifying multi-hop swaps across AMM pools."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for m in model.all_modules:
            if "router" in m.name.lower() or "aggregator" in m.name.lower() or "facade" in m.name.lower():
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FACADE_ROUTER",
                        description=f"Module '{m.name}' implements Facade pattern exposing high-level multi-pool swap aggregation entrypoints",
                        weight=0.92,
                        location=m.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACADE_ROUTER_AGGREGATOR,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=m.name,
                        target_kind="module",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=m.location,
                        evidences=evidences,
                    )
                )
        return detections


class FlyweightTypeTagRegistryRule(BaseRule):
    """Detects Flyweight pattern using phantom type parameters (struct Pool<phantom CoinA>)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            phantom_params = [p for p in s.type_parameters if "phantom" in p]
            if phantom_params:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FLYWEIGHT_PHANTOM",
                        description=f"Struct '{s.name}' implements Flyweight pattern using {len(phantom_params)} phantom type parameter(s) ({', '.join(phantom_params)})",
                        weight=0.95,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FLYWEIGHT_TYPE_TAG_REGISTRY,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class ProxyDelegateForwarderRule(BaseRule):
    """Detects Proxy pattern delegating execution rights via scoped sub-capabilities."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Delegate" in s.name or "Proxy" in s.name or "Operator" in s.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_PROXY_FORWARDER",
                        description=f"Struct '{s.name}' implements Proxy Delegation pattern forwarding authorized operator actions",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PROXY_DELEGATE_FORWARDER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections
