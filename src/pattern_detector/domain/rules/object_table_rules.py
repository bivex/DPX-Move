"""Sui Object Model and Aptos Global Account Storage architecture rules."""

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


class SuiObjectCentricDataModelRule(BaseRule):
    """Detects Sui Object-Centric Data Model (id: UID, transfer::share_object, transfer::transfer)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for s in model.all_structs:
            has_uid = any(f.name == "id" and "UID" in f.type_str for f in s.fields)
            if has_uid or ("key" in s.abilities and "UID" in s.raw_text):
                evidences = [
                    Evidence(
                        rule_code="SUI_OBJECT_CENTRIC_MODEL",
                        description=f"Struct '{s.name}' implements Sui Object-Centric Model with globally unique 'id: UID' and 'has key' ability",
                        weight=0.95,
                        location=s.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.SUI_OBJECT_CENTRIC_DATA_MODEL,
                        pattern_category=PatternCategory.OBJECT_TABLE_MODELS,
                        target_name=s.name,
                        target_kind="struct",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=s.location,
                        evidences=evidences,
                    )
                )
        return detections


class AptosAccountResourceStorageRule(BaseRule):
    """Detects Aptos Global Account Storage operations (move_to, borrow_global, exists)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_move_to or fn.has_borrow_global or "borrow_global" in fn.body or "move_to(" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="APTOS_ACCOUNT_STORAGE",
                        description=f"Function '{fn.name}' performs Aptos global storage access (move_to / borrow_global / exists)",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.APTOS_ACCOUNT_RESOURCE_STORAGE,
                        pattern_category=PatternCategory.OBJECT_TABLE_MODELS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class DynamicFieldExtensionRule(BaseRule):
    """Detects Dynamic Field extensions (dynamic_field::add, Table, SmartTable)."""

    DF_PATTERN = re.compile(r"\b(dynamic_field::|dynamic_object_field::|table::|smart_table::|bag::|object_bag::)\b")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_dynamic_field or self.DF_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="MOVE_DYNAMIC_FIELD_EXTENSION",
                        description=f"Function '{fn.name}' extends object state dynamically using Dynamic Fields / Tables",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DYNAMIC_FIELD_EXTENSION,
                        pattern_category=PatternCategory.OBJECT_TABLE_MODELS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class ModuleInitializerSingletonRule(BaseRule):
    """Detects module initializers (fun init in Sui or fun init_module in Aptos)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("init", "init_module"):
                evidences = [
                    Evidence(
                        rule_code="MOVE_MODULE_INITIALIZER",
                        description=f"Function '{fn.name}' implements Module Initializer executing exactly once upon contract publishing",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MODULE_INITIALIZER_SINGLETON,
                        pattern_category=PatternCategory.OBJECT_TABLE_MODELS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
