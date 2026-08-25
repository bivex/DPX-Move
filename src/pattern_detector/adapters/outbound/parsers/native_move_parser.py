"""High-speed native parser adapter for Move smart contract source code (.move)."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import (
    CodeModel,
    MoveConstant,
    MoveField,
    MoveFile,
    MoveFriend,
    MoveFunction,
    MoveModule,
    MoveSpec,
    MoveStruct,
    MoveUse,
)
from pattern_detector.domain.value_objects import SourceLocation
from pattern_detector.ports.outbound import ParserPort


def _split_top_level_commas(s: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in s:
        if char in "([{<":
            depth += 1
            current.append(char)
        elif char in ")]}>":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


class NativeMoveParserAdapter(ParserPort):
    """Single-pass robust parser extracting Move modules, structs, abilities, functions, and specs."""

    MODULE_DECL_PATTERN = re.compile(
        r"^\s*module\s+(?:(?P<pkg>[a-zA-Z0-9_]+)::)?(?P<name>[a-zA-Z0-9_]+)\s*\{"
    )
    USE_DECL_PATTERN = re.compile(
        r"^\s*use\s+(?P<path>[a-zA-Z0-9_:]+)(?:\s+as\s+(?P<alias>[a-zA-Z0-9_]+))?\s*;"
    )
    FRIEND_DECL_PATTERN = re.compile(
        r"^\s*friend\s+(?P<path>[a-zA-Z0-9_:]+)\s*;"
    )
    CONST_DECL_PATTERN = re.compile(
        r"^\s*const\s+(?P<name>[a-zA-Z0-9_]+)\s*:\s*(?P<type>[a-zA-Z0-9_]+)\s*=\s*(?P<val>[^;]+)\s*;"
    )
    STRUCT_HEADER_PATTERN = re.compile(
        r"^\s*(?:public\s+)?struct\s+(?P<name>[a-zA-Z0-9_]+)(?:<(?P<generics>[^>]+)>)?(?:\s+has\s+(?P<abilities>[a-zA-Z0-9_,\s]+))?\s*(?:\{|\;|\(?)"
    )
    FN_HEADER_PATTERN = re.compile(
        r"^\s*(?P<vis>public(?:\([a-zA-Z0-9_]+\))?\s+)?(?P<entry>entry\s+)?(?:inline\s+)?fun\s+(?P<name>[a-zA-Z0-9_]+)(?:<(?P<generics>[^>]+)>)?\s*\("
    )
    SPEC_HEADER_PATTERN = re.compile(
        r"^\s*spec\s+(?:(?P<kind>module|fun|struct)\s+)?(?P<target>[a-zA-Z0-9_]+)?\s*\{"
    )

    def parse_file(self, file_path: str, content: str) -> MoveFile:
        lines = content.splitlines()
        file_obj = MoveFile(file_path=file_path, raw_content=content, lines=lines)

        current_module: MoveModule | None = None
        current_function: MoveFunction | None = None
        current_func_body: list[str] = []
        func_brace_depth = 0

        current_struct: MoveStruct | None = None
        current_struct_body: list[str] = []
        struct_brace_depth = 0

        current_spec: MoveSpec | None = None
        current_spec_body: list[str] = []
        spec_brace_depth = 0

        for line_idx, raw_line in enumerate(lines, 1):
            trimmed = raw_line.strip()

            # Skip comments and empty lines
            if trimmed.startswith("//") or not trimmed:
                continue

            # Module Declaration
            mod_m = self.MODULE_DECL_PATTERN.match(trimmed)
            if mod_m and not current_module:
                pkg = mod_m.group("pkg") or ""
                m_name = mod_m.group("name")
                current_module = MoveModule(
                    name=m_name,
                    package_address=pkg,
                    location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                    raw_text=raw_line,
                )
                continue

            # If inside Module:
            if current_module:
                # 1. Use imports
                use_m = self.USE_DECL_PATTERN.match(trimmed)
                if use_m:
                    current_module.uses.append(
                        MoveUse(
                            module_path=use_m.group("path"),
                            alias=use_m.group("alias") or "",
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        )
                    )
                    continue

                # 2. Friend declarations
                friend_m = self.FRIEND_DECL_PATTERN.match(trimmed)
                if friend_m:
                    current_module.friends.append(
                        MoveFriend(
                            module_path=friend_m.group("path"),
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        )
                    )
                    continue

                # 3. Constants
                const_m = self.CONST_DECL_PATTERN.match(trimmed)
                if const_m:
                    c_name = const_m.group("name")
                    c_type = const_m.group("type")
                    c_val = const_m.group("val").strip()
                    is_err = c_name.startswith("E_") or c_name.startswith("ERR_") or "ERROR" in c_name
                    current_module.constants.append(
                        MoveConstant(
                            name=c_name,
                            type_str=c_type,
                            value_str=c_val,
                            is_error_code=is_err,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        )
                    )
                    continue

                # 4. Spec Block parsing
                if not current_spec and not current_function and not current_struct:
                    spec_m = self.SPEC_HEADER_PATTERN.match(trimmed)
                    if spec_m:
                        s_kind = spec_m.group("kind") or "module"
                        s_target = spec_m.group("target") or current_module.name
                        current_spec = MoveSpec(
                            target_name=s_target,
                            kind=s_kind,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                            raw_text=raw_line,
                        )
                        current_spec_body = [raw_line]
                        spec_brace_depth = raw_line.count("{") - raw_line.count("}")
                        if spec_brace_depth <= 0:
                            current_spec.raw_text = "\n".join(current_spec_body)
                            current_module.specs.append(current_spec)
                            current_spec = None
                            current_spec_body = []
                            spec_brace_depth = 0
                        continue

                if current_spec:
                    current_spec_body.append(raw_line)
                    spec_brace_depth += raw_line.count("{") - raw_line.count("}")
                    if "ensures " in raw_line:
                        current_spec.ensures.append(raw_line.strip())
                    if "aborts_if " in raw_line:
                        current_spec.aborts_if.append(raw_line.strip())
                    if "invariant " in raw_line:
                        current_spec.invariants.append(raw_line.strip())

                    if spec_brace_depth <= 0:
                        current_spec.raw_text = "\n".join(current_spec_body)
                        current_module.specs.append(current_spec)
                        current_spec = None
                        current_spec_body = []
                        spec_brace_depth = 0
                    continue

                # 5. Struct parsing
                if not current_struct and not current_function:
                    struct_m = self.STRUCT_HEADER_PATTERN.match(trimmed)
                    if struct_m:
                        s_name = struct_m.group("name")
                        generics_str = struct_m.group("generics") or ""
                        abilities_str = struct_m.group("abilities") or ""

                        generics = [g.strip() for g in _split_top_level_commas(generics_str) if g.strip()]
                        abilities = {a.strip() for a in abilities_str.split(",") if a.strip()}

                        current_struct = MoveStruct(
                            name=s_name,
                            abilities=abilities,
                            type_parameters=generics,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                            raw_text=raw_line,
                        )
                        current_struct_body = [raw_line]

                        # Handle single-line / empty struct (struct Name has drop {})
                        if "{" in raw_line and "}" in raw_line:
                            inner = raw_line[raw_line.index("{")+1:raw_line.rindex("}")]
                            for f_item in inner.split(";"):
                                f_trim = f_item.strip()
                                if ":" in f_trim:
                                    fname, ftype = f_trim.split(":", 1)
                                    current_struct.fields.append(MoveField(name=fname.strip(), type_str=ftype.strip()))
                            current_struct.raw_text = "\n".join(current_struct_body)
                            current_module.structs.append(current_struct)
                            current_struct = None
                            current_struct_body = []
                            struct_brace_depth = 0
                        elif "{" in raw_line:
                            struct_brace_depth = raw_line.count("{") - raw_line.count("}")
                        else:
                            # Struct ending with ; or empty (Move 2024 positional or empty)
                            current_module.structs.append(current_struct)
                            current_struct = None
                            current_struct_body = []
                            struct_brace_depth = 0
                        continue

                if current_struct:
                    current_struct_body.append(raw_line)
                    struct_brace_depth += raw_line.count("{") - raw_line.count("}")

                    if ":" in trimmed and not trimmed.startswith("//"):
                        f_part = trimmed.rstrip(",").rstrip(";").strip()
                        if ":" in f_part:
                            fname, ftype = f_part.split(":", 1)
                            current_struct.fields.append(MoveField(name=fname.strip(), type_str=ftype.strip()))

                    if struct_brace_depth <= 0:
                        current_struct.raw_text = "\n".join(current_struct_body)
                        current_module.structs.append(current_struct)
                        current_struct = None
                        current_struct_body = []
                        struct_brace_depth = 0
                    continue

                # 6. Function parsing
                if not current_function:
                    fn_m = self.FN_HEADER_PATTERN.match(trimmed)
                    if fn_m:
                        vis = (fn_m.group("vis") or "").strip() or "private"
                        is_entry = bool(fn_m.group("entry"))
                        fn_name = fn_m.group("name")
                        generics_str = fn_m.group("generics") or ""
                        generics = [g.strip() for g in _split_top_level_commas(generics_str) if g.strip()]

                        # Parse parameters with balanced parenthesis
                        rest = trimmed[fn_m.end():]
                        depth = 1
                        i = 0
                        while i < len(rest) and depth > 0:
                            if rest[i] == "(":
                                depth += 1
                            elif rest[i] == ")":
                                depth -= 1
                            i += 1

                        params_str = rest[:i-1] if i > 0 else ""
                        params = [p.strip() for p in _split_top_level_commas(params_str) if p.strip()]

                        current_function = MoveFunction(
                            name=fn_name,
                            visibility=vis,
                            is_entry=is_entry,
                            type_parameters=generics,
                            parameters=params,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                            raw_text=raw_line,
                        )
                        current_func_body = [raw_line]
                        func_brace_depth = raw_line.count("{") - raw_line.count("}")

                        if "assert!" in raw_line:
                            current_function.has_assert = True
                        if "transfer::" in raw_line:
                            current_function.has_transfer = True
                        if "event::emit" in raw_line:
                            current_function.has_event_emit = True
                        if "move_to" in raw_line:
                            current_function.has_move_to = True
                        if "borrow_global" in raw_line:
                            current_function.has_borrow_global = True
                        if "dynamic_field::" in raw_line:
                            current_function.has_dynamic_field = True

                        if func_brace_depth <= 0 and "{" in raw_line:
                            current_function.body = "\n".join(current_func_body)
                            current_module.functions.append(current_function)
                            current_function = None
                            current_func_body = []
                            func_brace_depth = 0
                        continue

                if current_function:
                    current_func_body.append(raw_line)
                    func_brace_depth += raw_line.count("{") - raw_line.count("}")

                    if "assert!" in raw_line:
                        current_function.has_assert = True
                    if "transfer::" in raw_line:
                        current_function.has_transfer = True
                    if "event::emit" in raw_line:
                        current_function.has_event_emit = True
                    if "move_to" in raw_line:
                        current_function.has_move_to = True
                    if "borrow_global" in raw_line:
                        current_function.has_borrow_global = True
                    if "dynamic_field::" in raw_line:
                        current_function.has_dynamic_field = True

                    if func_brace_depth <= 0:
                        current_function.body = "\n".join(current_func_body)
                        current_module.functions.append(current_function)
                        current_function = None
                        current_func_body = []
                        func_brace_depth = 0
                    continue

        if current_module:
            file_obj.modules.append(current_module)

        return file_obj

    def parse_codebase(self, files: list[tuple[str, str]], target_path: str = "") -> CodeModel:
        model = CodeModel(target_path=target_path)
        for fpath, content in files:
            m_file = self.parse_file(fpath, content)
            model.files.append(m_file)
        return model
