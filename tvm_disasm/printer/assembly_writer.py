"""
Assembly writer for converting AST to Fift assembly code.
"""
import json
import os
from typing import Any, Dict, List, Optional, Union

from pytoniq_core import Cell

from .base_writer import BaseWriter
from ..ast.ast import (
    BlockNode,
    ControlRegisterNode,
    GlobalVariableNode,
    InstructionNode,
    MethodNode,
    MethodReferenceNode,
    ProcedureNode,
    ProgramNode,
    ReferenceNode,
    ScalarNode,
    StackEntryNode,
)
from ..utils.known_methods import DEBUG_SYMBOLS


# Opcode renames for better readability
OPCODE_RENAMES = {
    "PUSHINT_4": "PUSHINT",
    "PUSHINT_8": "PUSHINT",
    "PUSHINT_16": "PUSHINT",
    "PUSHINT_LONG": "PUSHINT",
    "PUSHCONT_SHORT": "PUSHCONT",
    "THROW_SHORT": "THROW",
    "THROWIFNOT_SHORT": "THROWIFNOT",
    "THROWIF_SHORT": "THROWIF",
    "CALLDICT_LONG": "CALLDICT",
    "LSHIFTDIVMODR_VAR": "LSHIFTDIVMODR",
    "LSHIFT_VAR": "LSHIFT",
    "RSHIFTR_VAR": "RSHIFTR",
    "RSHIFT_VAR": "RSHIFT",
    "MULRSHIFTC_VAR": "MULRSHIFTC",
    "MULRSHIFTR_VAR": "MULRSHIFTR",
    "MULRSHIFT_VAR": "MULRSHIFT",
    "QMULRSHIFT_VAR": "QMULRSHIFT",
    "PUSHSLICE_LONG": "PUSHSLICE",
    "LSHIFTDIVR": "LSHIFT#DIVR",
    "LSHIFTDIVMODR": "LSHIFT#DIVMODR",
    "RSHIFTRMOD": "RSHIFTR#MOD",
    "QLSHIFTDIVMODR": "QLSHIFT#DIVMODR",
    "MULRSHIFTRMOD": "MULRSHIFTR#MOD",
    "LSHIFT": "LSHIFT#",
    "RSHIFT": "RSHIFT#",
    "MULRSHIFTR": "MULRSHIFTR#",
    "MULRSHIFTC": "MULRSHIFTC#",
    "MULMODPOW2": "MULMODPOW2#",
}


class AssemblyWriter:
    """
    Writes AST nodes to Fift assembly format.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize the assembly writer.

        Args:
            options: Writer options (useAliases, withoutHeader, etc.)
        """
        self.writer = BaseWriter()
        self.known_globals: Dict[int, str] = {}
        self.known_methods: Dict[int, str] = {}
        self.known_procedures: Dict[str, str] = {}
        self.options = options or {}

        debug_symbols = self.options.get('debugSymbols', DEBUG_SYMBOLS)
        for glob in debug_symbols.get('globals', []):
            index = glob.get('index')
            name = glob.get('name')
            if index is not None and name:
                self.known_globals[index] = name

        for proc in debug_symbols.get('procedures', []):
            method_id = proc.get('methodId')
            name = proc.get('name')
            cell_hash = proc.get('cellHash', '')
            if method_id is not None and name:
                self.known_methods[method_id] = name
            if cell_hash:
                self.known_procedures[cell_hash.lower()] = name

        # Load cp0 spec for aliases
        spec_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "spec",
            "cp0.json",
        )
        with open(spec_path, "r", encoding="utf-8") as f:
            self.cp0 = json.load(f)

        self.cp0_aliases: List[Dict[str, Any]] = self.cp0.get("aliases", [])
        self.cp0_instructions: Dict[str, Dict[str, Any]] = {
            instr["mnemonic"]: instr for instr in self.cp0.get("instructions", [])
        }

    def resolve_global_name(self, index: int) -> str:
        """Resolve global variable name."""
        return self.known_globals.get(index, str(index))

    def resolve_method_name(self, method_id: int) -> str:
        """Resolve method name."""
        return self.known_methods.get(method_id, f"?fun_{method_id}")

    def resolve_procedure_name(self, hash_str: str) -> str:
        """Resolve procedure name."""
        return self.known_procedures.get(hash_str.lower(), f"?fun_ref_{hash_str[:16]}")

    def _bits_to_hex(self, bits) -> str:
        """
        Convert TvmBitarray to Fift hex slice format with completion tag.

        Args:
            bits: TvmBitarray object

        Returns:
            Formatted hex string like "x{2_}" or "x{ABCD}"

        Note:
            Completion tag format: If bits length is not a multiple of 4,
            append a '1' bit followed by '0' bits to make it a multiple of 4.
            Then display as hex with '_' suffix.
        """
        if len(bits) == 0:
            return "x{}"

        binary_str = bits.to01()
        bit_len = len(binary_str)

        # Check if we need completion tag (not multiple of 4)
        needs_tag = (bit_len % 4) != 0

        # Add completion tag: '1' bit + padding '0' bits
        if needs_tag:
            padding_bits = 4 - (bit_len % 4)
            # Completion tag is '1' followed by (padding_bits - 1) '0's
            binary_str += '1' + '0' * (padding_bits - 1)

        # Convert to hex
        if binary_str:
            hex_val = hex(int(binary_str, 2))[2:].upper()
            # Ensure proper length (pad with leading zeros if needed)
            expected_hex_len = len(binary_str) // 4
            hex_val = hex_val.zfill(expected_hex_len)
        else:
            hex_val = ""

        # Add underscore if there was a completion tag
        if needs_tag:
            hex_val += "_"

        return f"x{{{hex_val}}}"

    def _write_cell_slice(self, cell: Cell) -> None:
        """
        Write a Cell as Fift slice notation, recursively expanding refs.

        Args:
            cell: Cell object to write
        """
        # Write the bits
        hex_str = self._bits_to_hex(cell.bits)
        self.writer.write_line(hex_str)

        # Recursively write refs
        for ref in cell.refs:
            self._write_cell_slice(ref)

    def write_program_node(self, node: ProgramNode) -> None:
        """Write a program node."""
        without_header = self.options.get('withoutHeader', True)

        if not without_header:
            self.writer.write_line("// Decompiled by tvm-dec")
            if node.with_refs:
                self.writer.write_line("// NOTE: This TVM assembly code was decompiled with the same code cells")
                self.writer.write_line("// extracted into dictionary procedures for better readability.")
                self.writer.write_line("// If you want to compile this code back, decompile without refs first (computeRefs: false)")

        self.writer.write_line('"Asm.fif" include')

        if not node.procedures and not node.methods:
            self.writer.write_line("<{")
            self.writer.indent(lambda: [
                self.write_instruction_node(inst)
                for inst in node.top_level_instructions
            ])
            self.writer.write("}>c")
            return

        self.writer.write_line("PROGRAM{")

        def write_program_body():
            # Sort methods and procedures
            methods = sorted(node.methods, key=lambda m: m.id)
            procedures = sorted(node.procedures, key=lambda p: p.hash)

            # Declare methods
            for method in methods:
                if method.id == 0:
                    self.writer.write_line(f"DECLPROC {self.resolve_method_name(method.id)}")
                else:
                    self.writer.write_line(f"{method.id} DECLMETHOD {self.resolve_method_name(method.id)}")

            # Declare procedures
            for procedure in procedures:
                self.writer.write_line(f"DECLPROC {self.resolve_procedure_name(procedure.hash)}")

            # Write method implementations
            for method in methods:
                self.write_method_node(method)

            # Write procedure implementations
            for procedure in procedures:
                self.write_procedure_node(procedure)

        self.writer.indent(write_program_body)
        self.writer.write_line("}END>c")

    def write_method_node(self, node: MethodNode) -> None:
        """Write a method node."""
        method_name = self.resolve_method_name(node.id)
        self.writer.write(f"{method_name} PROC:")
        self.write_block_node(node.body, False)
        self.writer.new_line()

    def write_procedure_node(self, node: ProcedureNode) -> None:
        """Write a procedure node."""
        procedure_name = self.resolve_procedure_name(node.hash)
        self.writer.write(f"{procedure_name} PROCREF:")
        self.write_block_node(node.body, False)
        self.writer.new_line()

    def write_block_node(self, node: BlockNode, top: bool) -> None:
        """Write a block node."""
        if top:
            self.writer.write_line('"Asm.fif" include')

        self.writer.write_line("<{")
        self.writer.indent(lambda: [
            self.write_instruction_node(inst)
            for inst in node.instructions
        ])

        if node.cell or top:
            self.writer.write("}>c")
        else:
            self.writer.write("}>")

    def _extract_argument_value(self, node: InstructionNode, index: int) -> Optional[Any]:
        """Return raw value for scalar-like arguments."""
        if index >= len(node.arguments):
            return None

        argument = node.arguments[index]
        if isinstance(argument, (ScalarNode, StackEntryNode, ControlRegisterNode, GlobalVariableNode)):
            return argument.value

        return None

    def _value_to_string(self, value: Any) -> str:
        """Convert argument values to string form mirroring opcode output."""
        if isinstance(value, Cell):
            return self._bits_to_hex(value.bits)
        return str(value)

    def maybe_specific_write(self, node: InstructionNode) -> Optional[str]:
        """
        Try to write instruction using a specific format or alias.

        Returns:
            Formatted string if special handling applies, None otherwise
        """
        opcode = node.opcode.definition["mnemonic"]
        first_arg = self._extract_argument_value(node, 0)
        second_arg = self._extract_argument_value(node, 1)

        if first_arg is None:
            return None

        original_instruction = self.cp0_instructions.get(opcode)
        if not original_instruction:
            return None

        alias = self._match_alias(opcode, node)
        if alias:
            return alias

        if (
            opcode in {"PUSHREF", "PUSHREFSLICE"}
            and isinstance(first_arg, str)
            and first_arg.startswith("x{")
        ):
            return f"<b x{first_arg[1:]} s, b> {opcode}"

        first_arg_str = self._value_to_string(first_arg)

        if opcode == "SETCP":
            return f"SETCP{first_arg_str}"

        if opcode == "XCHG_0I":
            return f"s0 s{first_arg_str} XCHG"

        if opcode == "XCHG_1I":
            return f"s1 s{first_arg_str} XCHG"

        if opcode == "XCHG_0I_LONG":
            return f"s0 {first_arg_str} s() XCHG"

        if opcode == "POP_LONG":
            return f"{first_arg_str} s() POP"

        if opcode == "XCHG_IJ" and second_arg is not None:
            return f"s{first_arg_str} s{self._value_to_string(second_arg)} XCHG"

        if opcode == "ADDCONST":
            if first_arg == 1:
                return "INC"
            if first_arg == -1:
                return "DEC"

        if opcode == "MULCONST" and first_arg == -1:
            return "NEGATE"

        if (
            original_instruction
            and len(original_instruction.get("bytecode", {}).get("operands", [])) == 1
        ):
            doc_fift = original_instruction.get("doc", {}).get("fift", "")
            if doc_fift.endswith("#"):
                return f"{first_arg_str} {opcode}#"
            if "#" in doc_fift and " " not in doc_fift:
                return f"{first_arg_str} {doc_fift}"

        if opcode == "CALLXARGS_VAR":
            return f"{first_arg_str} -1 CALLXARGS"

        if opcode == "PUSH_LONG":
            return f"{first_arg_str} s() PUSH"

        # Debug instructions
        if opcode == "DEBUG":
            if first_arg == 0x00:
                return "DUMPSTK"
            if first_arg == 0x14:
                return "STRDUMP"
            if second_arg is not None and isinstance(first_arg, int) and isinstance(second_arg, int):
                return f"{first_arg * 16 + second_arg} DEBUG"

        if opcode == "DEBUGSTR" and first_arg_str.startswith("x{") and first_arg_str.endswith("}"):
            hex_data = first_arg_str[2:-1].rstrip("_")
            try:
                buffer = bytes.fromhex(hex_data)
                return f"\"{buffer.decode()}\" DEBUGSTR"
            except (ValueError, UnicodeDecodeError):
                return None

        return None

    def write_instruction_node(self, node: InstructionNode) -> None:
        """Write an instruction node."""
        # Try specific formatting first
        specific = self.maybe_specific_write(node)
        if specific is not None:
            self.writer.write(specific)
            self.write_binary_representation_if_needed(node)
            self.writer.write_line("")
            return

        # Check if any argument is a Cell with refs (needs multi-line output)
        has_cell_with_refs = any(
            isinstance(arg, ScalarNode) and isinstance(arg.value, Cell) and len(arg.value.refs) > 0
            for arg in node.arguments
        )

        if has_cell_with_refs:
            for arg in node.arguments:
                if isinstance(arg, ScalarNode) and isinstance(arg.value, Cell):
                    self._write_cell_slice(arg.value)
                elif isinstance(arg, ScalarNode):
                    self.writer.write_line(f"{arg.value}")
                # Skip other argument types for now in multi-line mode

            # Write opcode name
            opcode_name = node.opcode.definition['mnemonic']
            final_name = OPCODE_RENAMES.get(opcode_name, opcode_name)
            self.writer.write_line(final_name)
        else:
            # Original single-line format
            # Write arguments
            for arg in node.arguments:
                if isinstance(arg, StackEntryNode):
                    if arg.value < 0:
                        self.writer.write(f"s({arg.value}) ")
                    else:
                        self.writer.write(f"s{arg.value} ")

                elif isinstance(arg, ControlRegisterNode):
                    if arg.value < 0:
                        self.writer.write(f"c({arg.value}) ")
                    else:
                        self.writer.write(f"c{arg.value} ")

                elif isinstance(arg, ScalarNode):
                    # Check if this is a Cell (slice)
                    if isinstance(arg.value, Cell):
                        # Format as Fift slice: x{hex_}
                        cell = arg.value
                        hex_str = self._bits_to_hex(cell.bits)
                        self.writer.write(f"{hex_str} ")
                    else:
                        self.writer.write(f"{arg.value} ")

                elif isinstance(arg, ReferenceNode):
                    self.writer.write(f"{self.resolve_procedure_name(arg.hash)} ")

                elif isinstance(arg, GlobalVariableNode):
                    self.writer.write(f"{self.resolve_global_name(arg.value)} ")

                elif isinstance(arg, MethodReferenceNode):
                    self.writer.write(f"{self.resolve_method_name(arg.method_id)} ")

                elif isinstance(arg, BlockNode):
                    self.write_block_node(arg, False)
                    self.writer.write(" ")

            # Write opcode name
            opcode_name = node.opcode.definition['mnemonic']
            final_name = OPCODE_RENAMES.get(opcode_name, opcode_name)
            self.writer.write(final_name)

            self.write_binary_representation_if_needed(node)
            self.writer.write_line("")

    def write_binary_representation_if_needed(self, node: InstructionNode) -> None:
        """Write binary representation as comment if enabled."""
        if not self.options.get('outputBitcodeAfterInstruction', False):
            return

        # Calculate spacing
        space = " " * max(1, 50 - self.writer.line_length())
        self.writer.write(f"{space}// 0x{node.opcode.definition['bytecode']['prefix']}")

        # Write operand bitcodes
        for arg in node.opcode.operands:
            self.writer.write(" ")
            if arg.type in ('numeric', 'ref', 'bigint'):
                self.writer.write(str(arg.bitcode))
            elif arg.type == 'subslice':
                self.writer.write(str(arg.value.bits))

    def write_node(
        self,
        node: Union[ProgramNode, MethodNode, ProcedureNode, BlockNode, InstructionNode],
        top: bool = False
    ) -> None:
        """Write any node type."""
        if isinstance(node, ProgramNode):
            self.write_program_node(node)
        elif isinstance(node, MethodNode):
            self.write_method_node(node)
        elif isinstance(node, ProcedureNode):
            self.write_procedure_node(node)
        elif isinstance(node, BlockNode):
            self.write_block_node(node, top)
        elif isinstance(node, InstructionNode):
            self.write_instruction_node(node)

    def output(self) -> str:
        """Get the final output."""
        return self.writer.end()

    @staticmethod
    def write(
        node: Union[ProgramNode, MethodNode, ProcedureNode, BlockNode],
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Write a node to Fift assembly format.

        Args:
            node: The node to write
            options: Writer options

        Returns:
            Fift assembly code as string
        """
        writer = AssemblyWriter(options)
        writer.write_node(node, top=True)
        return writer.output()
    def _match_alias(self, opcode: str, node: InstructionNode) -> Optional[str]:
        """Match instruction against cp0 aliases."""
        if not self.options.get("useAliases", True):
            return None

        instruction = self.cp0_instructions.get(opcode)
        if not instruction:
            return None

        for alias in self.cp0_aliases:
            if alias.get("alias_of") != opcode:
                continue
            if alias.get("mnemonic") == "DUMP":
                continue

            operands = alias.get("operands", {})
            matched = True

            for operand_name, expected in operands.items():
                operand_index = next(
                    (
                        idx
                        for idx, operand in enumerate(
                            instruction["bytecode"].get("operands", [])
                        )
                        if operand.get("name") == operand_name
                    ),
                    -1,
                )
                if operand_index == -1:
                    matched = False
                    break

                if operand_index >= len(node.arguments):
                    matched = False
                    break

                argument = node.arguments[operand_index]
                if getattr(argument, "type", None) not in {"scalar", "stack_entry", "control_register"}:
                    matched = False
                    break

                actual_value = getattr(argument, "value", None)
                if actual_value != expected:
                    matched = False
                    break

            if matched:
                return alias.get("mnemonic")

        return None
