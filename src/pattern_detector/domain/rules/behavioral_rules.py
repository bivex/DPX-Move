"""GoF Behavioral design pattern detection rules for Move (11/11)."""

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


class ChainOfResponsibilityValidationPipelineRule(BaseRule):
    """Detects Chain of Responsibility validation rules sequencing checks."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name.startswith("validate_") or "pipeline" in fn.name or "verify_rules" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_CHAIN_VALIDATION",
                        description=f"Function '{fn.name}' implements Chain of Responsibility validating transaction preconditions sequentially",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CHAIN_OF_RESPONSIBILITY_VALIDATION_PIPELINE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CommandExecutableActionRule(BaseRule):
    """Detects Command pattern encapsulating executable action payloads into structs."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Action" in s.name or "Command" in s.name or "Payload" in s.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_COMMAND_ACTION",
                        description=f"Struct '{s.name}' implements Command pattern encapsulating executable governance action payloads",
                        weight=0.90,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMMAND_EXECUTABLE_ACTION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class InterpreterBytecodeEvaluatorRule(BaseRule):
    """Detects Interpreter pattern evaluating on-chain rules or script buffers."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("eval", "evaluate", "interpret", "exec_instruction", "evaluate_script"):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_INTERPRETER_BYTECODE",
                        description=f"Function '{fn.name}' evaluates on-chain DSL rules or state transition byte instructions",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class IteratorCursorVectorScanRule(BaseRule):
    """Detects Iterator pattern scanning vectors with index cursors."""

    VEC_SCAN_PATTERN = re.compile(r"\bvector::(borrow|borrow_mut|pop_back|push_back)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.VEC_SCAN_PATTERN.search(fn.body) and ("while " in fn.body or "loop " in fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_ITERATOR_VECTOR_SCAN",
                        description=f"Function '{fn.name}' implements Iterator pattern traversing vector elements with bounded index cursors",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ITERATOR_CURSOR_VECTOR_SCAN,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class MediatorEscrowAtomicSwapRule(BaseRule):
    """Detects Mediator pattern mediating atomic asset swaps between counterparties."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Escrow" in s.name or "Swap" in s.name or "Settlement" in s.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_MEDIATOR_ESCROW",
                        description=f"Struct '{s.name}' implements Mediator pattern coordinating atomic asset exchange between counterparties",
                        weight=0.90,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class MementoCheckpointSnapshotRule(BaseRule):
    """Detects Memento state snapshots for historical epochs or voting weights."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Checkpoint" in s.name or "Snapshot" in s.name or "EpochRecord" in s.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_MEMENTO_SNAPSHOT",
                        description=f"Struct '{s.name}' captures historical balance/state checkpoints (Memento pattern)",
                        weight=0.90,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEMENTO_CHECKPOINT_SNAPSHOT,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class ObserverEventEmissionRule(BaseRule):
    """Detects Observer pattern emitting typed events (event::emit)."""

    EVENT_PATTERN = re.compile(r"\b(event::emit|event::emit_event)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_event_emit or self.EVENT_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_OBSERVER_EVENTS",
                        description=f"Function '{fn.name}' implements Observer pattern broadcasting state change notifications via typed events",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.OBSERVER_EVENT_EMISSION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StateMachineVaultLifecycleRule(BaseRule):
    """Detects State Machine protocol lifecycle states."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "State" in s.name or "Lifecycle" in s.name or "Phase" in s.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STATE_LIFECYCLE",
                        description=f"Struct '{s.name}' implements State Machine pattern coordinating protocol operational phases",
                        weight=0.88,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STATE_MACHINE_VAULT_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class StrategyYieldHarvestInjectionRule(BaseRule):
    """Detects Strategy pattern injecting interchangeable yield/rebalance logic."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            if "Strategy" in s.name or "Harvest" in s.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STRATEGY_INJECTION",
                        description=f"Struct '{s.name}' implements Strategy pattern providing interchangeable yield/harvest allocation algorithms",
                        weight=0.90,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STRATEGY_YIELD_HARVEST_INJECTION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class TemplateMethodHookLifecycleRule(BaseRule):
    """Detects Template Method lifecycle coordinating execution with pre/post hooks."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("execute", "process", "settle") and any(f"before_{fn.name}" in fn.body or f"after_{fn.name}" in fn.body or "check_preconditions" in fn.body for f in [fn]):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_TEMPLATE_METHOD",
                        description=f"Function '{fn.name}' implements Template Method pattern coordinating execution with pre/post hook checks",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class VisitorHookReceiverRule(BaseRule):
    """Detects Flashloan callback receiver hook patterns."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "flash" in fn.name.lower() or "callback" in fn.name.lower() or "hook" in fn.name.lower():
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_VISITOR_HOOK",
                        description=f"Function '{fn.name}' implements Visitor Callback Hook receiver for flashloans / cross-contract composability",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.VISITOR_HOOK_RECEIVER,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
