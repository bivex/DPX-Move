"""Unit tests for Move SOLID principles and code smells."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_move_parser import NativeMoveParserAdapter
from pattern_detector.domain.rules.solid_principles_rules import (
    FatResourceInterfaceIspRule,
    HardcodedAddressOcpRule,
    MonolithicModuleSrpRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_monolithic_module_srp() -> None:
    funcs = "\n".join([f"    public fun fn_{i}() {{}}" for i in range(16)])
    code = f"""
module package::mega_module {{
{funcs}
}}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("mega.move", code)])

    rule = MonolithicModuleSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MONOLITHIC_MODULE_SRP


def test_fat_resource_interface_isp() -> None:
    fields = "\n".join([f"        f_{i}: u64," for i in range(11)])
    code = f"""
module package::fat_struct {{
    struct FatResource has key {{
{fields}
    }}
}}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("fat.move", code)])

    rule = FatResourceInterfaceIspRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FAT_RESOURCE_INTERFACE_ISP


def test_hardcoded_address_ocp() -> None:
    code = """
module package::magic_addr {
    public fun get_admin(): address {
        @0x1122334455667788
    }
}
"""
    parser = NativeMoveParserAdapter()
    model = parser.parse_codebase([("addr.move", code)])

    rule = HardcodedAddressOcpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.HARDCODED_ADDRESS_OCP
