"""Comprehensive pattern catalog and metadata for Move language static analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pattern_detector.domain.value_objects import PatternCategory, PatternType


@dataclass(frozen=True)
class PatternDefinition:
    """Detailed architectural specification of a Move pattern or hazard."""

    type: PatternType
    category: PatternCategory
    name: str
    description: str
    move_version: str = "Move 2024 / Aptos / Sui / Initia / Movement"
    recommendation: str = ""


PATTERN_CATALOG: dict[PatternType, PatternDefinition] = {
    # 1. Move Idiomatic, Linear Types & Abilities
    PatternType.RESOURCE_LINEAR_TYPE_SAFETY: PatternDefinition(
        type=PatternType.RESOURCE_LINEAR_TYPE_SAFETY,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Resource Linear Type Safety",
        description="Linear types enforced by Move VM: structs with 'key' and without 'drop' preventing double-spend and resource destruction.",
        recommendation="Do not grant 'drop' or 'copy' abilities to financial or stateful custody resources.",
    ),
    PatternType.STRUCT_ABILITY_COMPOSITION: PatternDefinition(
        type=PatternType.STRUCT_ABILITY_COMPOSITION,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Struct Ability Composition",
        description="Explicit ability typing (has key, store, copy, drop) defining resource lifecycle and storage semantics.",
        recommendation="Carefully restrict abilities on structs to uphold the principle of least privilege.",
    ),
    PatternType.WITNESS_TYPE_AUTHORIZATION: PatternDefinition(
        type=PatternType.WITNESS_TYPE_AUTHORIZATION,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Witness Type Authorization (OTW)",
        description="One-Time Witness (OTW) pattern consuming single-use drop structs during module initialization.",
        recommendation="Use One-Time Witness to guarantee single-instance treasury caps and coin initialization.",
    ),
    PatternType.HOT_POTATO_TRANSIENT_RECEIPT: PatternDefinition(
        type=PatternType.HOT_POTATO_TRANSIENT_RECEIPT,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Hot Potato Transient Receipt",
        description="Struct without any abilities (no key, store, copy, drop) forcing same-transaction repayment (Flashloans).",
        recommendation="Use Hot Potato structs for flashloans, atomic swaps, and multi-step transaction pipelines.",
    ),
    PatternType.CAPABILITY_ACCESS_CONTROL: PatternDefinition(
        type=PatternType.CAPABILITY_ACCESS_CONTROL,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Capability Access Control Pattern",
        description="Access control by passing an explicit capability reference (&AdminCap) instead of fragile address checks.",
        recommendation="Prefer capability passing over address whitelisting for modular, transferable governance.",
    ),
    PatternType.FRIEND_MODULE_VISIBILITY: PatternDefinition(
        type=PatternType.FRIEND_MODULE_VISIBILITY,
        category=PatternCategory.MOVE_IDIOMATIC_RESOURCES,
        name="Friend Module Visibility Scope",
        description="Scoping internal package functions with public(friend) / public(package) to prevent external invocation.",
        recommendation="Use public(package) or public(friend) for internal multi-module contract orchestration.",
    ),

    # 2. Aptos vs. Sui Move Object & Table Models
    PatternType.SUI_OBJECT_CENTRIC_DATA_MODEL: PatternDefinition(
        type=PatternType.SUI_OBJECT_CENTRIC_DATA_MODEL,
        category=PatternCategory.OBJECT_TABLE_MODELS,
        name="Sui Object-Centric Data Model",
        description="Object model with unique UID fields ('id: UID') transferred via transfer::transfer or transfer::share_object.",
        recommendation="Distinguish between owned objects and shared objects to maximize Sui consensus parallelism.",
    ),
    PatternType.APTOS_ACCOUNT_RESOURCE_STORAGE: PatternDefinition(
        type=PatternType.APTOS_ACCOUNT_RESOURCE_STORAGE,
        category=PatternCategory.OBJECT_TABLE_MODELS,
        name="Aptos Account Resource Storage",
        description="Global storage operations under account addresses: move_to, borrow_global, borrow_global_mut, exists.",
        recommendation="Ensure proper signer authorization before calling move_to or borrow_global_mut.",
    ),
    PatternType.DYNAMIC_FIELD_EXTENSION: PatternDefinition(
        type=PatternType.DYNAMIC_FIELD_EXTENSION,
        category=PatternCategory.OBJECT_TABLE_MODELS,
        name="Dynamic Field & Table Extension",
        description="Extending object schemas at runtime using dynamic_field::add or Table/SmartTable collections.",
        recommendation="Use dynamic fields for extensible plugins and scalable key-value storage.",
    ),
    PatternType.MODULE_INITIALIZER_SINGLETON: PatternDefinition(
        type=PatternType.MODULE_INITIALIZER_SINGLETON,
        category=PatternCategory.OBJECT_TABLE_MODELS,
        name="Module Initializer Singleton",
        description="Module one-shot bootstrapper (init in Sui / init_module in Aptos) executing exactly once upon publishing.",
        recommendation="Initialize admin capabilities and treasury caps inside module init functions.",
    ),

    # 3. Move Prover & Formal Verification
    PatternType.MOVE_PROVER_FORMAL_SPEC: PatternDefinition(
        type=PatternType.MOVE_PROVER_FORMAL_SPEC,
        category=PatternCategory.FORMAL_SPEC_PROVER,
        name="Move Prover Formal Verification Specification",
        description="Formal mathematical proof specifications (spec module, spec fun, ensures, aborts_if, invariant).",
        recommendation="Write Move Prover specifications for mission-critical vault accounting invariants.",
    ),
    PatternType.ABORT_CODE_DOMAIN_ENUMS: PatternDefinition(
        type=PatternType.ABORT_CODE_DOMAIN_ENUMS,
        category=PatternCategory.FORMAL_SPEC_PROVER,
        name="Typed Domain Abort Error Codes",
        description="Explicit error constant declarations (const E_NOT_AUTHORIZED: u64 = 1; assert!(..., E_...)).",
        recommendation="Use uppercase descriptive error constants (const E_INSUFFICIENT_BALANCE: u64 = 100).",
    ),
    PatternType.INVARIANT_STATE_ASSERTION: PatternDefinition(
        type=PatternType.INVARIANT_STATE_ASSERTION,
        category=PatternCategory.FORMAL_SPEC_PROVER,
        name="Invariant State Assertion",
        description="Post-condition and invariant assertions guaranteeing state validity across execution branches.",
        recommendation="Assert mathematical invariants before and after state transformations.",
    ),

    # 4. Creational Patterns (5/5)
    PatternType.SINGLETON_CAPABILITY_VAULT: PatternDefinition(
        type=PatternType.SINGLETON_CAPABILITY_VAULT,
        category=PatternCategory.CREATIONAL,
        name="Singleton Capability Vault",
        description="Singleton pattern issuing a single, non-copyable capability struct during module initialization.",
        recommendation="Store singletons in shared objects or root module storage.",
    ),
    PatternType.FACTORY_RESOURCE_MINT_CONSTRUCTOR: PatternDefinition(
        type=PatternType.FACTORY_RESOURCE_MINT_CONSTRUCTOR,
        category=PatternCategory.CREATIONAL,
        name="Factory Resource Mint Constructor",
        description="Factory pattern packing and constructing new resource instances from raw arguments.",
        recommendation="Encapsulate resource struct packing in dedicated factory functions.",
    ),
    PatternType.ABSTRACT_FACTORY_POOL_CREATOR: PatternDefinition(
        type=PatternType.ABSTRACT_FACTORY_POOL_CREATOR,
        category=PatternCategory.CREATIONAL,
        name="Abstract Factory Liquidity Pool Creator",
        description="Abstract factory creating generic liquidity pools and market vaults parameterized by coin types.",
        recommendation="Parameterize pool creation with generic type arguments (CoinA, CoinB).",
    ),
    PatternType.BUILDER_MULTISIG_PROPOSAL: PatternDefinition(
        type=PatternType.BUILDER_MULTISIG_PROPOSAL,
        category=PatternCategory.CREATIONAL,
        name="Builder Multi-step Governance Proposal",
        description="Builder pattern incrementally constructing a proposal or batch transaction before execution.",
        recommendation="Use builder structs to stage multi-step governance actions before quorum voting.",
    ),
    PatternType.PROTOTYPE_RESOURCE_CLONE_SPLIT: PatternDefinition(
        type=PatternType.PROTOTYPE_RESOURCE_CLONE_SPLIT,
        category=PatternCategory.CREATIONAL,
        name="Prototype Resource Split & Merge",
        description="Prototype pattern creating new resource portions via balance splitting (coin::split / balance::split).",
        recommendation="Use coin::split and coin::join for granular coin balance lifecycle management.",
    ),

    # 5. Structural Patterns (7/7)
    PatternType.ADAPTER_ORACLE_WRAPPER: PatternDefinition(
        type=PatternType.ADAPTER_ORACLE_WRAPPER,
        category=PatternCategory.STRUCTURAL,
        name="Adapter Oracle Price Wrapper",
        description="Adapter pattern transforming Pyth/Chainlink/Switchboard oracle feeds into uniform price structs.",
        recommendation="Standardize external price feeds behind an oracle adapter interface.",
    ),
    PatternType.BRIDGE_CROSS_CHAIN_PORTAL: PatternDefinition(
        type=PatternType.BRIDGE_CROSS_CHAIN_PORTAL,
        category=PatternCategory.STRUCTURAL,
        name="Bridge Cross-Chain Portal",
        description="Decoupling cross-chain communication abstractions from specific relayer or validator bridges.",
        recommendation="Separate message validation logic from payload execution in cross-chain portals.",
    ),
    PatternType.COMPOSITE_BUNDLE_BAG: PatternDefinition(
        type=PatternType.COMPOSITE_BUNDLE_BAG,
        category=PatternCategory.STRUCTURAL,
        name="Composite Heterogeneous Resource Bag",
        description="Composite pattern aggregating heterogeneous resource types using sui::bag or Table collections.",
        recommendation="Use Bag or ObjectBag for extensible multi-asset vaults.",
    ),
    PatternType.DECORATOR_YIELD_VAULT_BOOSTER: PatternDefinition(
        type=PatternType.DECORATOR_YIELD_VAULT_BOOSTER,
        category=PatternCategory.STRUCTURAL,
        name="Decorator Yield Vault Booster",
        description="Decorator pattern wrapping base staking deposits with reward multiplier metadata.",
        recommendation="Wrap base staking positions with boost layers rather than modifying core pool logic.",
    ),
    PatternType.FACADE_ROUTER_AGGREGATOR: PatternDefinition(
        type=PatternType.FACADE_ROUTER_AGGREGATOR,
        category=PatternCategory.STRUCTURAL,
        name="Facade DEX Router Aggregator",
        description="Unified entrypoint facade abstracting multi-hop routing across individual AMM pools.",
        recommendation="Provide high-level swap and liquidity routing functions in a facade module.",
    ),
    PatternType.FLYWEIGHT_TYPE_TAG_REGISTRY: PatternDefinition(
        type=PatternType.FLYWEIGHT_TYPE_TAG_REGISTRY,
        category=PatternCategory.STRUCTURAL,
        name="Flyweight Phantom Type Tag Registry",
        description="Using phantom type parameters (struct Pool<phantom CoinA>) eliminating runtime metadata storage.",
        recommendation="Use phantom type parameters for zero-byte compile-time coin differentiation.",
    ),
    PatternType.PROXY_DELEGATE_FORWARDER: PatternDefinition(
        type=PatternType.PROXY_DELEGATE_FORWARDER,
        category=PatternCategory.STRUCTURAL,
        name="Proxy Capability Delegate Forwarder",
        description="Proxy pattern delegating execution rights from owner capabilities to authorized operator roles.",
        recommendation="Issue scoped sub-capabilities for delegated operator actions.",
    ),

    # 6. Behavioral Patterns (11/11)
    PatternType.CHAIN_OF_RESPONSIBILITY_VALIDATION_PIPELINE: PatternDefinition(
        type=PatternType.CHAIN_OF_RESPONSIBILITY_VALIDATION_PIPELINE,
        category=PatternCategory.BEHAVIORAL,
        name="Chain of Responsibility Validation Pipeline",
        description="Passing transaction requests through sequenced validation rule checks.",
        recommendation="Structure complex order validation as chained filter functions.",
    ),
    PatternType.COMMAND_EXECUTABLE_ACTION: PatternDefinition(
        type=PatternType.COMMAND_EXECUTABLE_ACTION,
        category=PatternCategory.BEHAVIORAL,
        name="Command Executable Action Payload",
        description="Encapsulating executable actions into payload structs passed to governance executors.",
        recommendation="Model DAO governance actions as strongly typed Command structs.",
    ),
    PatternType.INTERPRETER_BYTECODE_EVALUATOR: PatternDefinition(
        type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
        category=PatternCategory.BEHAVIORAL,
        name="Interpreter On-Chain Rule Evaluator",
        description="Evaluating on-chain DSL or state machine transition instructions from byte buffers.",
        recommendation="Use table-driven interpreters for programmable on-chain settlement logic.",
    ),
    PatternType.ITERATOR_CURSOR_VECTOR_SCAN: PatternDefinition(
        type=PatternType.ITERATOR_CURSOR_VECTOR_SCAN,
        category=PatternCategory.BEHAVIORAL,
        name="Iterator Cursor Vector Scan",
        description="Cursor-based bounded iteration over vector elements (vector::borrow, vector::length).",
        recommendation="Bound vector iteration loops to prevent transaction gas exhaustion.",
    ),
    PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP: PatternDefinition(
        type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
        category=PatternCategory.BEHAVIORAL,
        name="Mediator Escrow Atomic Swap",
        description="Central escrow module mediating atomic token exchanges between distrusting counterparties.",
        recommendation="Use atomic escrow shared objects to eliminate counterparty risk.",
    ),
    PatternType.MEMENTO_CHECKPOINT_SNAPSHOT: PatternDefinition(
        type=PatternType.MEMENTO_CHECKPOINT_SNAPSHOT,
        category=PatternCategory.BEHAVIORAL,
        name="Memento State Checkpoint Snapshot",
        description="Recording historical balance or epoch checkpoints for governance and reward distributions.",
        recommendation="Store historical epoch snapshots in indexed tables for retrospective queries.",
    ),
    PatternType.OBSERVER_EVENT_EMISSION: PatternDefinition(
        type=PatternType.OBSERVER_EVENT_EMISSION,
        category=PatternCategory.BEHAVIORAL,
        name="Observer Typed Event Emission",
        description="Observer pattern broadcasting typed event structs (event::emit) for off-chain indexers.",
        recommendation="Emit strongly typed event structs for all critical state mutations.",
    ),
    PatternType.STATE_MACHINE_VAULT_LIFECYCLE: PatternDefinition(
        type=PatternType.STATE_MACHINE_VAULT_LIFECYCLE,
        category=PatternCategory.BEHAVIORAL,
        name="State Machine Vault Lifecycle",
        description="Finite State Machine enforcing protocol states (Pending, Active, Paused, Settled).",
        recommendation="Enforce explicit state transition guards in stateful smart contracts.",
    ),
    PatternType.STRATEGY_YIELD_HARVEST_INJECTION: PatternDefinition(
        type=PatternType.STRATEGY_YIELD_HARVEST_INJECTION,
        category=PatternCategory.BEHAVIORAL,
        name="Strategy Yield Harvest Injection",
        description="Strategy pattern injecting interchangeable yield/rebalance algorithms into vaults.",
        recommendation="Parameterize vault rebalancing with interchangeable strategy modules.",
    ),
    PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE: PatternDefinition(
        type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
        category=PatternCategory.BEHAVIORAL,
        name="Template Method Lifecycle Hooks",
        description="Fixed execution skeleton coordinating entrypoints with pre/post execution hooks.",
        recommendation="Coordinate trade execution with pre-trade and post-trade hook checks.",
    ),
    PatternType.VISITOR_HOOK_RECEIVER: PatternDefinition(
        type=PatternType.VISITOR_HOOK_RECEIVER,
        category=PatternCategory.BEHAVIORAL,
        name="Visitor Flashloan Receiver Hook",
        description="Callback receiver invoked by flashloan or lending pools during borrow transactions.",
        recommendation="Validate flashloan callback receipts with Hot Potato structs.",
    ),

    # 7. Move Security Hazards
    PatternType.UNPROTECTED_RESOURCE_MUTATION_HAZARD: PatternDefinition(
        type=PatternType.UNPROTECTED_RESOURCE_MUTATION_HAZARD,
        category=PatternCategory.MOVE_SECURITY_HAZARDS,
        name="Unprotected Resource Mutation Hazard",
        description="Public entry function taking mutable reference (&mut Resource) without capability or signer verification.",
        recommendation="Require capability proof (&AdminCap) or signer authentication before mutating shared state.",
    ),
    PatternType.ARBITRARY_COIN_DRAIN_HAZARD: PatternDefinition(
        type=PatternType.ARBITRARY_COIN_DRAIN_HAZARD,
        category=PatternCategory.MOVE_SECURITY_HAZARDS,
        name="Arbitrary Coin Drain Hazard",
        description="Public entry function transferring or minting coins without recipient or sender authorization checks.",
        recommendation="Verify signer identity and balance sufficiency before transferring coins.",
    ),
    PatternType.MISSING_ABORT_ASSERTION_HAZARD: PatternDefinition(
        type=PatternType.MISSING_ABORT_ASSERTION_HAZARD,
        category=PatternCategory.MOVE_SECURITY_HAZARDS,
        name="Missing Abort Assertion Hazard",
        description="Branching logic executing critical state updates without assert! verification.",
        recommendation="Add explicit assert! statements guarding precondition invariants.",
    ),
    PatternType.VECTOR_OVERFLOW_DOS_HAZARD: PatternDefinition(
        type=PatternType.VECTOR_OVERFLOW_DOS_HAZARD,
        category=PatternCategory.MOVE_SECURITY_HAZARDS,
        name="Vector Overflow Denial of Service Hazard",
        description="Unbounded loop over dynamic vector risking transaction gas limit exhaustion.",
        recommendation="Bound iteration loops and use paginated vector access.",
    ),

    # 8. SOLID Principles & Smells
    PatternType.MONOLITHIC_MODULE_SRP: PatternDefinition(
        type=PatternType.MONOLITHIC_MODULE_SRP,
        category=PatternCategory.PRINCIPLE,
        name="Monolithic Module SRP Violation",
        description="Module declaring excessive structs (>= 8) or functions (>= 15), violating Single Responsibility.",
        recommendation="Decompose large modules into cohesive sub-modules using friend visibility.",
    ),
    PatternType.FAT_RESOURCE_INTERFACE_ISP: PatternDefinition(
        type=PatternType.FAT_RESOURCE_INTERFACE_ISP,
        category=PatternCategory.PRINCIPLE,
        name="Fat Resource Interface ISP Violation",
        description="Struct declaring excessive fields (>= 10), violating Interface Segregation.",
        recommendation="Split large structs into smaller composable resources with dynamic fields.",
    ),
    PatternType.HARDCODED_ADDRESS_OCP: PatternDefinition(
        type=PatternType.HARDCODED_ADDRESS_OCP,
        category=PatternCategory.PRINCIPLE,
        name="Hardcoded Literal Address OCP Violation",
        description="Hardcoding literal hex addresses (@0x...) instead of named package addresses.",
        recommendation="Use named addresses in Move.toml rather than hardcoding hex addresses in source code.",
    ),
}
