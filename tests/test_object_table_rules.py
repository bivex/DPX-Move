"""Unit tests for Sui Object Model and Aptos Global Account Storage rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.object_table_rules import (
    AptosAccountResourceStorageRule,
    DynamicFieldExtensionRule,
    ModuleInitializerSingletonRule,
    SuiObjectCentricDataModelRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_sui_object_centric_data_model() -> None:
    code = """
module package::sui_vault {
    struct SuiVault has key {
        id: UID,
        balance: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("vault.move", code)])

    rule = SuiObjectCentricDataModelRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.SUI_OBJECT_CENTRIC_DATA_MODEL


def test_aptos_account_resource_storage() -> None:
    code = """
module package::aptos_vault {
    public entry fun init_vault(account: &signer) {
        move_to(account, Vault { balance: 0 });
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("vault.move", code)])

    rule = AptosAccountResourceStorageRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.APTOS_ACCOUNT_RESOURCE_STORAGE


def test_dynamic_field_extension() -> None:
    code = """
module package::extension {
    public fun add_custom_field(parent: &mut UID, key: u64, val: u64) {
        dynamic_field::add(parent, key, val);
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("ext.move", code)])

    rule = DynamicFieldExtensionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DYNAMIC_FIELD_EXTENSION


def test_module_initializer_singleton() -> None:
    code = """
module package::init_demo {
    fun init(witness: INIT_DEMO, ctx: &mut TxContext) {
        transfer::transfer(AdminCap { id: object::new(ctx) }, tx_context::sender(ctx));
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("init.move", code)])

    rule = ModuleInitializerSingletonRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MODULE_INITIALIZER_SINGLETON
