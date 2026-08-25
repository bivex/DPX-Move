"""Tests verifying zero false positives on clean, idiomatic Move smart contracts."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.security_rules import (
    ArbitraryCoinDrainHazardRule,
    MissingAbortAssertionHazardRule,
    UnprotectedResourceMutationHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import MonolithicModuleSrpRule


def test_clean_capability_guarded_mutation_no_hazard() -> None:
    code = """
module package::safe_vault {
    public entry fun mutate_vault(_cap: &AdminCap, vault: &mut Vault) {
        vault.balance = 100;
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("safe.move", code)])

    rule = UnprotectedResourceMutationHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_signer_guarded_drain_no_hazard() -> None:
    code = """
module package::safe_transfer {
    public entry fun transfer_funds(account: &signer, to: address) {
        transfer::transfer(Coin { val: 100 }, to);
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("safe.move", code)])

    rule = ArbitraryCoinDrainHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_assert_guarded_branch_no_hazard() -> None:
    code = """
module package::safe_branch {
    public fun modify_storage(addr: address) {
        assert!(exists<Vault>(addr), 1);
        let v = borrow_global_mut<Vault>(addr);
        v.balance = 100;
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("safe.move", code)])

    rule = MissingAbortAssertionHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_small_module_no_srp() -> None:
    code = """
module package::small_module {
    public fun add(a: u64, b: u64): u64 { a + b }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("small.move", code)])

    rule = MonolithicModuleSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0
