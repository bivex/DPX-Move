"""Unit tests for Move Idiomatic, Linear Types & Ability Composition rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.idiomatic_rules import (
    CapabilityAccessControlRule,
    FriendModuleVisibilityRule,
    HotPotatoTransientReceiptRule,
    ResourceLinearTypeSafetyRule,
    StructAbilityCompositionRule,
    WitnessTypeAuthorizationRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_resource_linear_type_safety() -> None:
    code = """
module package::vault {
    struct Vault has key {
        id: u64,
        balance: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("vault.move", code)])

    rule = ResourceLinearTypeSafetyRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.RESOURCE_LINEAR_TYPE_SAFETY


def test_struct_ability_composition() -> None:
    code = """
module package::coin {
    struct Coin<phantom T> has key, store {
        id: u64,
        value: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("coin.move", code)])

    rule = StructAbilityCompositionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STRUCT_ABILITY_COMPOSITION


def test_witness_type_authorization() -> None:
    code = """
module package::my_coin {
    struct MY_COIN has drop {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("coin.move", code)])

    rule = WitnessTypeAuthorizationRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.WITNESS_TYPE_AUTHORIZATION


def test_hot_potato_transient_receipt() -> None:
    code = """
module package::flashloan {
    struct FlashReceipt {
        amount: u64,
        fee: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("flash.move", code)])

    rule = HotPotatoTransientReceiptRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.HOT_POTATO_TRANSIENT_RECEIPT


def test_capability_access_control() -> None:
    code = """
module package::governance {
    struct AdminCap has key, store {
        id: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("gov.move", code)])

    rule = CapabilityAccessControlRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CAPABILITY_ACCESS_CONTROL


def test_friend_module_visibility() -> None:
    code = """
module package::core {
    friend package::router;

    public(friend) fun internal_settle() {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("core.move", code)])

    rule = FriendModuleVisibilityRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FRIEND_MODULE_VISIBILITY
