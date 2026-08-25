"""Rules registry and aggregation factory for Move pattern detector."""

from __future__ import annotations

from pattern_detector.domain.rules.base import BaseRule
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
from pattern_detector.domain.rules.formal_prover_rules import (
    AbortCodeDomainEnumsRule,
    InvariantStateAssertionRule,
    MoveProverFormalSpecRule,
)
from pattern_detector.domain.rules.idiomatic_rules import (
    CapabilityAccessControlRule,
    FriendModuleVisibilityRule,
    HotPotatoTransientReceiptRule,
    ResourceLinearTypeSafetyRule,
    StructAbilityCompositionRule,
    WitnessTypeAuthorizationRule,
)
from pattern_detector.domain.rules.object_table_rules import (
    AptosAccountResourceStorageRule,
    DynamicFieldExtensionRule,
    ModuleInitializerSingletonRule,
    SuiObjectCentricDataModelRule,
)
from pattern_detector.domain.rules.security_rules import (
    ArbitraryCoinDrainHazardRule,
    MissingAbortAssertionHazardRule,
    UnprotectedResourceMutationHazardRule,
    VectorOverflowDosHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import (
    FatResourceInterfaceIspRule,
    HardcodedAddressOcpRule,
    MonolithicModuleSrpRule,
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

DEFAULT_RULES: list[type[BaseRule]] = [
    # 1. Move Idiomatic, Linear Types & Abilities (6)
    ResourceLinearTypeSafetyRule,
    StructAbilityCompositionRule,
    WitnessTypeAuthorizationRule,
    HotPotatoTransientReceiptRule,
    CapabilityAccessControlRule,
    FriendModuleVisibilityRule,

    # 2. Aptos vs. Sui Move Object & Table Models (4)
    SuiObjectCentricDataModelRule,
    AptosAccountResourceStorageRule,
    DynamicFieldExtensionRule,
    ModuleInitializerSingletonRule,

    # 3. Move Prover & Formal Verification (3)
    MoveProverFormalSpecRule,
    AbortCodeDomainEnumsRule,
    InvariantStateAssertionRule,

    # 4. Creational Patterns (5/5)
    SingletonCapabilityVaultRule,
    FactoryResourceMintConstructorRule,
    AbstractFactoryPoolCreatorRule,
    BuilderMultisigProposalRule,
    PrototypeResourceCloneSplitRule,

    # 5. Structural Patterns (7/7)
    AdapterOracleWrapperRule,
    BridgeCrossChainPortalRule,
    CompositeBundleBagRule,
    DecoratorYieldVaultBoosterRule,
    FacadeRouterAggregatorRule,
    FlyweightTypeTagRegistryRule,
    ProxyDelegateForwarderRule,

    # 6. Behavioral Patterns (11/11)
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

    # 7. Move Security Hazards (4)
    UnprotectedResourceMutationHazardRule,
    ArbitraryCoinDrainHazardRule,
    MissingAbortAssertionHazardRule,
    VectorOverflowDosHazardRule,

    # 8. SOLID Principles & Smells (3)
    MonolithicModuleSrpRule,
    FatResourceInterfaceIspRule,
    HardcodedAddressOcpRule,
]


def get_default_rules() -> list[BaseRule]:
    """Instantiate and return full suite of default Move rules."""
    return [rule_cls() for rule_cls in DEFAULT_RULES]
