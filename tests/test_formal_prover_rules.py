"""Unit tests for Move Prover Formal Verification and Specification rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.formal_prover_rules import (
    AbortCodeDomainEnumsRule,
    InvariantStateAssertionRule,
    MoveProverFormalSpecRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_move_prover_formal_spec() -> None:
    code = """
module package::math {
    public fun safe_add(a: u64, b: u64): u64 {
        a + b
    }

    spec safe_add {
        ensures result == a + b;
        aborts_if a + b > MAX_U64;
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("math.move", code)])

    rule = MoveProverFormalSpecRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MOVE_PROVER_FORMAL_SPEC


def test_abort_code_domain_enums() -> None:
    code = """
module package::errors {
    const E_NOT_AUTHORIZED: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("errors.move", code)])

    rule = AbortCodeDomainEnumsRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ABORT_CODE_DOMAIN_ENUMS


def test_invariant_state_assertion() -> None:
    code = """
module package::guard {
    public fun check_amount(amount: u64) {
        assert!(amount > 0, 100);
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("guard.move", code)])

    rule = InvariantStateAssertionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.INVARIANT_STATE_ASSERTION
