"""Unit tests for all 23 GoF Creational, Structural, and Behavioral patterns in Move."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.behavioral_rules import (
    ChainOfResponsibilityValidationPipelineRule,
    CommandExecutableActionRule,
    InterpreterBytecodeEvaluatorRule,
    IteratorCursorVectorScanRule,
    MediatorEscrowAtomicSwapRule,
    MementoCheckpointSnapshotRule,
    ObserverEventEmissionRule,
    StateMachineVaultLifecycleRule,
    StrategyYieldHarvestInjectionRule,
    TemplateMethodHookLifecycleRule,
    VisitorHookReceiverRule,
)
from pattern_detector.domain.rules.creational_rules import (
    AbstractFactoryPoolCreatorRule,
    BuilderMultisigProposalRule,
    FactoryResourceMintConstructorRule,
    PrototypeResourceCloneSplitRule,
    SingletonCapabilityVaultRule,
)
from pattern_detector.domain.rules.structural_rules import (
    AdapterOracleWrapperRule,
    BridgeCrossChainPortalRule,
    CompositeBundleBagRule,
    DecoratorYieldVaultBoosterRule,
    FacadeRouterAggregatorRule,
    FlyweightTypeTagRegistryRule,
    ProxyDelegateForwarderRule,
)
from pattern_detector.domain.value_objects import PatternType


# --- Creational (5/5) ---

def test_singleton_capability_vault() -> None:
    code = """
module package::vault {
    struct MasterCap has key, store { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("vault.move", code)])

    rule = SingletonCapabilityVaultRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.SINGLETON_CAPABILITY_VAULT


def test_factory_resource_mint_constructor() -> None:
    code = """
module package::minter {
    public fun mint_coin(val: u64): Coin {
        Coin { val }
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("minter.move", code)])

    rule = FactoryResourceMintConstructorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACTORY_RESOURCE_MINT_CONSTRUCTOR


def test_abstract_factory_pool_creator() -> None:
    code = """
module package::amm {
    public fun create_pool<CoinA, CoinB>(fee: u64) {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("amm.move", code)])

    rule = AbstractFactoryPoolCreatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ABSTRACT_FACTORY_POOL_CREATOR


def test_builder_multisig_proposal() -> None:
    code = """
module package::gov {
    struct ProposalBuilder has key {
        actions: vector<u64>,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("gov.move", code)])

    rule = BuilderMultisigProposalRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BUILDER_MULTISIG_PROPOSAL


def test_prototype_resource_clone_split() -> None:
    code = """
module package::split_demo {
    public fun take_fee(c: &mut Coin, fee: u64): Coin {
        coin::split(c, fee)
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("split.move", code)])

    rule = PrototypeResourceCloneSplitRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROTOTYPE_RESOURCE_CLONE_SPLIT


# --- Structural (7/7) ---

def test_adapter_oracle_wrapper() -> None:
    code = """
module package::oracle {
    struct PythOracleAdapter has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("oracle.move", code)])

    rule = AdapterOracleWrapperRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ADAPTER_ORACLE_WRAPPER


def test_bridge_cross_chain_portal() -> None:
    code = """
module package::bridge {
    struct WormholePortal has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("bridge.move", code)])

    rule = BridgeCrossChainPortalRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BRIDGE_CROSS_CHAIN_PORTAL


def test_composite_bundle_bag() -> None:
    code = """
module package::bag_demo {
    struct AssetBundleBag has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("bag.move", code)])

    rule = CompositeBundleBagRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMPOSITE_BUNDLE_BAG


def test_decorator_yield_vault_booster() -> None:
    code = """
module package::boost {
    struct StakingLockBooster has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("boost.move", code)])

    rule = DecoratorYieldVaultBoosterRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DECORATOR_YIELD_VAULT_BOOSTER


def test_facade_router_aggregator() -> None:
    code = """
module package::swap_router {
    public fun swap_exact() {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("router.move", code)])

    rule = FacadeRouterAggregatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACADE_ROUTER_AGGREGATOR


def test_flyweight_type_tag_registry() -> None:
    code = """
module package::pool {
    struct Pool<phantom CoinA, phantom CoinB> has key {
        id: u64,
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("pool.move", code)])

    rule = FlyweightTypeTagRegistryRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FLYWEIGHT_TYPE_TAG_REGISTRY


def test_proxy_delegate_forwarder() -> None:
    code = """
module package::proxy {
    struct OperatorDelegate has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("proxy.move", code)])

    rule = ProxyDelegateForwarderRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROXY_DELEGATE_FORWARDER


# --- Behavioral (11/11) ---

def test_chain_of_responsibility_validation_pipeline() -> None:
    code = """
module package::rules {
    public fun validate_order_pipeline() {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("rules.move", code)])

    rule = ChainOfResponsibilityValidationPipelineRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CHAIN_OF_RESPONSIBILITY_VALIDATION_PIPELINE


def test_command_executable_action() -> None:
    code = """
module package::dao {
    struct GovernanceAction has key, store { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("dao.move", code)])

    rule = CommandExecutableActionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMMAND_EXECUTABLE_ACTION


def test_interpreter_bytecode_evaluator() -> None:
    code = """
module package::vm {
    public fun exec_instruction(op: u8) {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("vm.move", code)])

    rule = InterpreterBytecodeEvaluatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.INTERPRETER_BYTECODE_EVALUATOR


def test_iterator_cursor_vector_scan() -> None:
    code = """
module package::scan {
    public fun sum_elements(v: &vector<u64>): u64 {
        let mut i = 0;
        let mut sum = 0;
        while (i < 10) {
            sum = sum + *vector::borrow(v, i);
            i = i + 1;
        };
        sum
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("scan.move", code)])

    rule = IteratorCursorVectorScanRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ITERATOR_CURSOR_VECTOR_SCAN


def test_mediator_escrow_atomic_swap() -> None:
    code = """
module package::escrow {
    struct EscrowSwap has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("escrow.move", code)])

    rule = MediatorEscrowAtomicSwapRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP


def test_memento_checkpoint_snapshot() -> None:
    code = """
module package::history {
    struct EpochCheckpoint has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("history.move", code)])

    rule = MementoCheckpointSnapshotRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEMENTO_CHECKPOINT_SNAPSHOT


def test_observer_event_emission() -> None:
    code = """
module package::events {
    public fun notify_deposit(amount: u64) {
        event::emit(DepositEvent { amount });
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("events.move", code)])

    rule = ObserverEventEmissionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.OBSERVER_EVENT_EMISSION


def test_state_machine_vault_lifecycle() -> None:
    code = """
module package::fsm {
    struct VaultLifecycleState has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("fsm.move", code)])

    rule = StateMachineVaultLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STATE_MACHINE_VAULT_LIFECYCLE


def test_strategy_yield_harvest_injection() -> None:
    code = """
module package::strat {
    struct CompoundHarvestStrategy has key { id: u64 }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("strat.move", code)])

    rule = StrategyYieldHarvestInjectionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STRATEGY_YIELD_HARVEST_INJECTION


def test_template_method_hook_lifecycle() -> None:
    code = """
module package::hook {
    public fun execute() {
        check_preconditions();
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("hook.move", code)])

    rule = TemplateMethodHookLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE


def test_visitor_hook_receiver() -> None:
    code = """
module package::flash {
    public fun flash_repay_callback() {}
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("flash.move", code)])

    rule = VisitorHookReceiverRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.VISITOR_HOOK_RECEIVER
