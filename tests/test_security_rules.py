"""Unit tests for Move smart contract security hazards."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.security_rules import (
    ArbitraryCoinDrainHazardRule,
    MissingAbortAssertionHazardRule,
    UnprotectedResourceMutationHazardRule,
    VectorOverflowDosHazardRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_unprotected_resource_mutation_hazard() -> None:
    code = """
module package::unsafe_vault {
    public entry fun drain_state(vault: &mut Vault) {
        vault.balance = 0;
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("unsafe.move", code)])

    rule = UnprotectedResourceMutationHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UNPROTECTED_RESOURCE_MUTATION_HAZARD


def test_arbitrary_coin_drain_hazard() -> None:
    code = """
module package::unsafe_drain {
    public entry fun steal_funds(to: address) {
        transfer::transfer(Coin { val: 1000 }, to);
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("unsafe.move", code)])

    rule = ArbitraryCoinDrainHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ARBITRARY_COIN_DRAIN_HAZARD


def test_missing_abort_assertion_hazard() -> None:
    code = """
module package::unsafe_branch {
    public fun modify_storage(addr: address) {
        if (true) {
            let v = borrow_global_mut<Vault>(addr);
            v.balance = 100;
        }
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("unsafe.move", code)])

    rule = MissingAbortAssertionHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MISSING_ABORT_ASSERTION_HAZARD


def test_vector_overflow_dos_hazard() -> None:
    code = """
module package::unsafe_loop {
    public fun process_all(v: &vector<u64>) {
        while (true) {
            let len = vector::length(v);
        }
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("unsafe.move", code)])

    rule = VectorOverflowDosHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.VECTOR_OVERFLOW_DOS_HAZARD
