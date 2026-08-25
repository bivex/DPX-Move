"""Domain CodeModel entities representing Move modules, structs, functions, abilities, and specs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pattern_detector.domain.value_objects import SourceLocation


@dataclass
class MoveField:
    """Field definition inside a Move struct."""

    name: str
    type_str: str


@dataclass
class MoveStruct:
    """Move struct definition with abilities (has key, store, copy, drop)."""

    name: str
    abilities: set[str] = field(default_factory=set)  # {"key", "store", "copy", "drop"}
    type_parameters: list[str] = field(default_factory=list)  # e.g. ["phantom CoinA", "T"]
    fields: list[MoveField] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""

    @property
    def is_resource(self) -> bool:
        """A linear resource has 'key' but lacks 'drop' and 'copy'."""
        return "key" in self.abilities and "drop" not in self.abilities and "copy" not in self.abilities

    @property
    def is_hot_potato(self) -> bool:
        """A hot potato has NO abilities at all."""
        return len(self.abilities) == 0

    @property
    def is_witness(self) -> bool:
        """One-Time Witness typically has 'drop' (or 'drop, store') and uppercase name matching module."""
        return "drop" in self.abilities and "key" not in self.abilities

    @property
    def is_capability(self) -> bool:
        """Capability struct typically named *Cap or *Capability."""
        return self.name.endswith("Cap") or self.name.endswith("Capability") or "Admin" in self.name


@dataclass
class MoveFunction:
    """Move function definition (public, public(friend), entry, fun)."""

    name: str
    visibility: str = "private"  # "public", "public(friend)", "public(package)", "private"
    is_entry: bool = False
    type_parameters: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    return_type: str = ""
    body: str = ""
    acquires: list[str] = field(default_factory=list)
    has_assert: bool = False
    has_transfer: bool = False
    has_event_emit: bool = False
    has_move_to: bool = False
    has_borrow_global: bool = False
    has_dynamic_field: bool = False
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class MoveConstant:
    """Move constant declaration (e.g. const E_NOT_AUTHORIZED: u64 = 1;)."""

    name: str
    type_str: str = ""
    value_str: str = ""
    is_error_code: bool = False
    location: SourceLocation | None = None


@dataclass
class MoveSpec:
    """Formal Move Prover specification block."""

    target_name: str
    kind: str  # "module", "fun", "struct"
    ensures: list[str] = field(default_factory=list)
    aborts_if: list[str] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class MoveUse:
    """Import declaration (use sui::object::{Self, UID};)."""

    module_path: str
    alias: str = ""
    location: SourceLocation | None = None


@dataclass
class MoveFriend:
    """Friend declaration (friend package::other_module;)."""

    module_path: str
    location: SourceLocation | None = None


@dataclass
class MoveModule:
    """Move module definition (module package::module_name { ... })."""

    name: str
    package_address: str = ""
    uses: list[MoveUse] = field(default_factory=list)
    friends: list[MoveFriend] = field(default_factory=list)
    structs: list[MoveStruct] = field(default_factory=list)
    functions: list[MoveFunction] = field(default_factory=list)
    constants: list[MoveConstant] = field(default_factory=list)
    specs: list[MoveSpec] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class MoveFile:
    """Parsed Move source file (.move)."""

    file_path: str
    raw_content: str
    lines: list[str] = field(default_factory=list)
    modules: list[MoveModule] = field(default_factory=list)


@dataclass
class CodeModel:
    """Aggregated structural model of a scanned Move codebase."""

    target_path: str = ""
    files: list[MoveFile] = field(default_factory=list)

    @property
    def all_modules(self) -> list[MoveModule]:
        return [m for f in self.files for m in f.modules]

    @property
    def all_structs(self) -> list[MoveStruct]:
        return [s for m in self.all_modules for s in m.structs]

    @property
    def all_functions(self) -> list[MoveFunction]:
        return [fn for m in self.all_modules for fn in m.functions]

    @property
    def all_constants(self) -> list[MoveConstant]:
        return [c for m in self.all_modules for c in m.constants]

    @property
    def all_specs(self) -> list[MoveSpec]:
        return [spec for m in self.all_modules for spec in m.specs]
