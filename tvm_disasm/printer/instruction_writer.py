"""
Instruction writer for outputting detailed opcode information.
"""
from typing import Dict, Optional, Any, Union, List
from .base_writer import BaseWriter
from ..ast.ast import (
    ProgramNode, MethodNode, ProcedureNode, BlockNode, InstructionNode,
    StackEntryNode, ControlRegisterNode, GlobalVariableNode, ScalarNode,
    ReferenceNode, MethodReferenceNode
)
from pytoniq_core import Cell


class InstructionWriter:
    """
    Writes detailed instruction information from AST nodes.
    Shows opcode mnemonics, operands, and metadata.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        """
        Initialize the instruction writer.

        Args:
            options: Writer options (showBytecode, showOffsets, etc.)
        """
        self.writer = BaseWriter()
        self.known_globals: Dict[int, str] = {}
        self.known_methods: Dict[int, str] = {}
        self.known_procedures: Dict[str, str] = {}
        self.options = options or {}
        self.instruction_count = 0

    def resolve_global_name(self, index: int) -> str:
        """Resolve global variable name."""
        return self.known_globals.get(index, str(index))

    def resolve_method_name(self, method_id: int) -> str:
        """Resolve method name."""
        return self.known_methods.get(method_id, f"?fun_{method_id}")

    def resolve_procedure_name(self, hash_str: str) -> str:
        """Resolve procedure name."""
        return self.known_procedures.get(hash_str, f"?fun_ref_{hash_str[:16]}")

    def _format_argument(self, arg) -> str:
        """Format a single argument for display."""
        if isinstance(arg, StackEntryNode):
            return f"s{arg.value}" if arg.value >= 0 else f"s({arg.value})"
        elif isinstance(arg, ControlRegisterNode):
            return f"c{arg.value}" if arg.value >= 0 else f"c({arg.value})"
        elif isinstance(arg, ScalarNode):
            if isinstance(arg.value, Cell):
                # Format cell as hex
                bits = arg.value.bits
                if len(bits) == 0:
                    return "x{}"
                binary_str = bits.to01()
                hex_val = hex(int(binary_str, 2))[2:].upper() if binary_str else ""
                return f"x{{{hex_val}}}"
            else:
                return str(arg.value)
        elif isinstance(arg, ReferenceNode):
            return f"ref:{self.resolve_procedure_name(arg.hash)}"
        elif isinstance(arg, GlobalVariableNode):
            return f"global:{self.resolve_global_name(arg.value)}"
        elif isinstance(arg, MethodReferenceNode):
            return f"method:{self.resolve_method_name(arg.method_id)}"
        elif isinstance(arg, BlockNode):
            return f"<block:{len(arg.instructions)} instructions>"
        else:
            return str(arg)

    def write_instruction_node(self, node: InstructionNode) -> None:
        """Write detailed instruction information."""
        self.instruction_count += 1

        # Instruction header
        if self.options.get('showOffsets', False):
            self.writer.write(f"[{self.instruction_count:4d}] @{node.offset:4d} ({node.length:2d}b) ")
        else:
            self.writer.write(f"[{self.instruction_count:4d}] ")

        # Opcode mnemonic
        opcode = node.opcode.definition['mnemonic']
        self.writer.write(f"{opcode:<20s}")

        # Arguments
        if node.arguments:
            args_str = ", ".join(self._format_argument(arg) for arg in node.arguments)
            self.writer.write(f" | args: {args_str}")

        # Bytecode (if enabled)
        if self.options.get('showBytecode', False):
            prefix = node.opcode.definition.get('bytecode', {}).get('prefix', '')
            if prefix:
                self.writer.write(f" | bytecode: 0x{prefix}")

        self.writer.write_line("")

        # Show operand details (if enabled)
        if self.options.get('showOperandDetails', False) and node.opcode.operands:
            for i, operand in enumerate(node.opcode.operands):
                operand_type = operand.type
                if operand_type == 'numeric':
                    self.writer.write_line(f"      operand[{i}]: {operand_type} = {operand.value} (bitcode: {operand.bitcode})")
                elif operand_type == 'bigint':
                    self.writer.write_line(f"      operand[{i}]: {operand_type} = {operand.value}")
                elif operand_type == 'ref':
                    self.writer.write_line(f"      operand[{i}]: {operand_type} = <Cell>")
                elif operand_type == 'subslice':
                    self.writer.write_line(f"      operand[{i}]: {operand_type} = <Slice>")

    def write_block_node(self, node: BlockNode, label: str = "Block") -> None:
        """Write a block of instructions."""
        self.writer.write_line(f"\n{label} (hash: {node.hash[:16]}..., {len(node.instructions)} instructions):")
        self.writer.write_line("-" * 80)

        for inst in node.instructions:
            self.write_instruction_node(inst)

    def write_method_node(self, node: MethodNode) -> None:
        """Write a method."""
        method_name = self.resolve_method_name(node.id)
        self.write_block_node(node.body, f"Method {node.id} ({method_name})")

    def write_procedure_node(self, node: ProcedureNode) -> None:
        """Write a procedure."""
        procedure_name = self.resolve_procedure_name(node.hash)
        self.write_block_node(node.body, f"Procedure ({procedure_name})")

    def write_program_node(self, node: ProgramNode) -> None:
        """Write a complete program."""
        self.writer.write_line("=" * 80)
        self.writer.write_line("TVM PROGRAM DISASSEMBLY")
        self.writer.write_line("=" * 80)

        if node.methods:
            self.writer.write_line(f"\nMethods: {len(node.methods)}")
        if node.procedures:
            self.writer.write_line(f"Procedures: {len(node.procedures)}")
        if node.top_level_instructions:
            self.writer.write_line(f"Top-level instructions: {len(node.top_level_instructions)}")

        # Write top-level instructions
        if node.top_level_instructions:
            self.write_block_node(
                BlockNode(instructions=node.top_level_instructions, hash="top_level"),
                "Top-level Instructions"
            )

        # Write methods (sorted by ID)
        for method in sorted(node.methods, key=lambda m: m.id):
            self.instruction_count = 0  # Reset counter for each method
            self.write_method_node(method)

        # Write procedures (sorted by hash)
        for procedure in sorted(node.procedures, key=lambda p: p.hash):
            self.instruction_count = 0  # Reset counter for each procedure
            self.write_procedure_node(procedure)

        self.writer.write_line("\n" + "=" * 80)

    def write_node(
        self,
        node: Union[ProgramNode, MethodNode, ProcedureNode, BlockNode, InstructionNode]
    ) -> None:
        """Write any node type."""
        if isinstance(node, ProgramNode):
            self.write_program_node(node)
        elif isinstance(node, MethodNode):
            self.write_method_node(node)
        elif isinstance(node, ProcedureNode):
            self.write_procedure_node(node)
        elif isinstance(node, BlockNode):
            self.write_block_node(node)
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
        Write instruction details for a node.

        Args:
            node: The node to write
            options: Writer options:
                - showOffsets: Show instruction offsets and lengths
                - showBytecode: Show bytecode hex values
                - showOperandDetails: Show detailed operand information

        Returns:
            Formatted instruction details as string
        """
        writer = InstructionWriter(options)
        writer.write_node(node)
        return writer.output()
