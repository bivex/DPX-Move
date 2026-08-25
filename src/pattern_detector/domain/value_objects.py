"""Value objects, Enums, and domain primitives for Move language static analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    """Broad architectural classification for Move patterns and findings."""

    MOVE_IDIOMATIC_RESOURCES = "move_idiomatic_resources"
    OBJECT_TABLE_MODELS = "object_table_models"
    FORMAL_SPEC_PROVER = "formal_spec_prover"
    CREATIONAL = "creational"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    MOVE_SECURITY_HAZARDS = "move_security_hazards"
    PRINCIPLE = "principle"


class PatternType(str, Enum):
    """Exhaustive catalog of Move patterns, linear resources, abilities, and hazards."""

    # 1. Move Idiomatic, Linear Types & Abilities (6)
    RESOURCE_LINEAR_TYPE_SAFETY = "resource_linear_type_safety"
    STRUCT_ABILITY_COMPOSITION = "struct_ability_composition"
    WITNESS_TYPE_AUTHORIZATION = "witness_type_authorization"
    HOT_POTATO_TRANSIENT_RECEIPT = "hot_potato_transient_receipt"
    CAPABILITY_ACCESS_CONTROL = "capability_access_control"
    FRIEND_MODULE_VISIBILITY = "friend_module_visibility"

    # 2. Aptos vs. Sui Move Object & Table Models (4)
    SUI_OBJECT_CENTRIC_DATA_MODEL = "sui_object_centric_data_model"
    APTOS_ACCOUNT_RESOURCE_STORAGE = "aptos_account_resource_storage"
    DYNAMIC_FIELD_EXTENSION = "dynamic_field_extension"
    MODULE_INITIALIZER_SINGLETON = "module_initializer_singleton"

    # 3. Move Prover & Formal Verification (3)
    MOVE_PROVER_FORMAL_SPEC = "move_prover_formal_spec"
    ABORT_CODE_DOMAIN_ENUMS = "abort_code_domain_enums"
    INVARIANT_STATE_ASSERTION = "invariant_state_assertion"

    # 4. Creational Patterns (5/5)
    SINGLETON_CAPABILITY_VAULT = "singleton_capability_vault"
    FACTORY_RESOURCE_MINT_CONSTRUCTOR = "factory_resource_mint_constructor"
    ABSTRACT_FACTORY_POOL_CREATOR = "abstract_factory_pool_creator"
    BUILDER_MULTISIG_PROPOSAL = "builder_multisig_proposal"
    PROTOTYPE_RESOURCE_CLONE_SPLIT = "prototype_resource_clone_split"

    # 5. Structural Patterns (7/7)
    ADAPTER_ORACLE_WRAPPER = "adapter_oracle_wrapper"
    BRIDGE_CROSS_CHAIN_PORTAL = "bridge_cross_chain_portal"
    COMPOSITE_BUNDLE_BAG = "composite_bundle_bag"
    DECORATOR_YIELD_VAULT_BOOSTER = "decorator_yield_vault_booster"
    FACADE_ROUTER_AGGREGATOR = "facade_router_aggregator"
    FLYWEIGHT_TYPE_TAG_REGISTRY = "flyweight_type_tag_registry"
    PROXY_DELEGATE_FORWARDER = "proxy_delegate_forwarder"

    # 6. Behavioral Patterns (11/11)
    CHAIN_OF_RESPONSIBILITY_VALIDATION_PIPELINE = "chain_of_responsibility_validation_pipeline"
    COMMAND_EXECUTABLE_ACTION = "command_executable_action"
    INTERPRETER_BYTECODE_EVALUATOR = "interpreter_bytecode_evaluator"
    ITERATOR_CURSOR_VECTOR_SCAN = "iterator_cursor_vector_scan"
    MEDIATOR_ESCROW_ATOMIC_SWAP = "mediator_escrow_atomic_swap"
    MEMENTO_CHECKPOINT_SNAPSHOT = "memento_checkpoint_snapshot"
    OBSERVER_EVENT_EMISSION = "observer_event_emission"
    STATE_MACHINE_VAULT_LIFECYCLE = "state_machine_vault_lifecycle"
    STRATEGY_YIELD_HARVEST_INJECTION = "strategy_yield_harvest_injection"
    TEMPLATE_METHOD_HOOK_LIFECYCLE = "template_method_hook_lifecycle"
    VISITOR_HOOK_RECEIVER = "visitor_hook_receiver"

    # 7. Move Security Hazards (4)
    UNPROTECTED_RESOURCE_MUTATION_HAZARD = "unprotected_resource_mutation_hazard"
    ARBITRARY_COIN_DRAIN_HAZARD = "arbitrary_coin_drain_hazard"
    MISSING_ABORT_ASSERTION_HAZARD = "missing_abort_assertion_hazard"
    VECTOR_OVERFLOW_DOS_HAZARD = "vector_overflow_dos_hazard"

    # 8. SOLID Principles & Smells (3)
    MONOLITHIC_MODULE_SRP = "monolithic_module_srp"
    FAT_RESOURCE_INTERFACE_ISP = "fat_resource_interface_isp"
    HARDCODED_ADDRESS_OCP = "hardcoded_address_ocp"


class ConfidenceLevel(str, Enum):
    """Categorical confidence level ranking."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


@dataclass(frozen=True)
class SourceLocation:
    """Precise source code location in a Move file (.move)."""

    file_path: str
    line: int
    column: int = 1

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"


@dataclass
class Evidence:
    """Individual heuristic or signal contributing to pattern detection."""

    rule_code: str
    description: str
    weight: float
    location: SourceLocation | None = None


@dataclass
class Confidence:
    """Aggregated detection confidence score and heuristic evidence trail."""

    score: float
    evidences: list[Evidence] = field(default_factory=list)

    @property
    def level(self) -> ConfidenceLevel:
        if self.score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        if self.score >= 0.70:
            return ConfidenceLevel.HIGH
        if self.score >= 0.50:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @property
    def percentage_str(self) -> str:
        return f"{int(round(self.score * 100))}%"
