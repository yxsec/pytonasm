"""
Core disassembler for TVM bytecode.
"""
from dataclasses import dataclass
from typing import List, Optional, Callable, Dict
from pytoniq_core import Cell, Slice
from .operand_loader import decode_instruction, DecodedInstruction
from ..ast.ast import (
    InstructionNode, BlockNode, ProgramNode, MethodNode, ProcedureNode,
    create_instruction, create_block, create_method, create_procedure, create_program,
    ScalarNode, ReferenceNode, MethodReferenceNode
)


@dataclass
class DecompiledInstruction:
    """Represents a decompiled instruction with metadata"""
    op: DecodedInstruction
    hash: str
    offset: int
    length: int


# Pseudo instruction for INLINECALLDICT (Fift opcode, not TVM)
PSEUDO_INLINECALLDICT = {
    'mnemonic': 'INLINECALLDICT',
    'doc': {
        'fift': 'INLINECALLDICT',
        'description': 'Inline call to dictionary method (pseudo-opcode for decompiler)'
    },
    'bytecode': {
        'prefix': '',
        'operands': []
    }
}


def disassemble(
    source: Cell,
    offset_bits: int = 0,
    offset_refs: int = 0,
    limit_bits: Optional[int] = None,
    limit_refs: Optional[int] = None
) -> List[DecompiledInstruction]:
    """
    Disassemble a cell into a list of instructions.

    Args:
        source: The cell to disassemble
        offset_bits: Bit offset to start from
        offset_refs: Reference offset to start from
        limit_bits: Maximum bits to process
        limit_refs: Maximum references to process

    Returns:
        List of decompiled instructions
    """
    # Calculate actual limits
    bits_limit = limit_bits if limit_bits is not None else len(source.bits) - offset_bits
    refs_limit = limit_refs if limit_refs is not None else len(source.refs) - offset_refs

    # Create a slice of the source cell
    slice_obj = source.begin_parse()

    # Track initial state for offset calculation
    initial_bits = slice_obj.remaining_bits
    initial_refs = slice_obj.remaining_refs

    # Skip to offset
    if offset_bits > 0:
        slice_obj.skip_bits(offset_bits)
    if offset_refs > 0:
        for _ in range(offset_refs):
            slice_obj.load_ref()

    instructions = []
    hash_str = source.hash.hex()

    # Process bits
    bits_processed = 0
    while slice_obj.remaining_bits > 0 and bits_processed < bits_limit:
        opcode_offset = initial_bits - slice_obj.remaining_bits
        opcode = decode_instruction(source, slice_obj)
        opcode_length = (initial_bits - slice_obj.remaining_bits) - opcode_offset

        instructions.append(DecompiledInstruction(
            op=opcode,
            hash=hash_str,
            offset=opcode_offset,
            length=opcode_length
        ))

        bits_processed = (initial_bits - slice_obj.remaining_bits) - offset_bits

    # Process remaining refs recursively
    refs_processed = 0
    while slice_obj.remaining_refs > 0 and refs_processed < refs_limit:
        ref_cell = slice_obj.load_ref()
        instructions.extend(disassemble(ref_cell))
        refs_processed += 1

    return instructions


def disassemble_and_process(
    source: Cell,
    offset_bits: int = 0,
    offset_refs: int = 0,
    limit_bits: Optional[int] = None,
    limit_refs: Optional[int] = None,
    on_cell_reference: Optional[Callable[[Cell], None]] = None
) -> BlockNode:
    """
    Disassemble and process a cell into a BlockNode.

    This is the core function of the decompiler that handles references,
    calls, and operands correctly.

    Args:
        source: The cell to disassemble
        offset_bits: Bit offset to start from
        offset_refs: Reference offset to start from
        limit_bits: Maximum bits to process
        limit_refs: Maximum references to process
        on_cell_reference: Callback for cell references

    Returns:
        BlockNode containing processed instructions
    """
    opcodes = disassemble(source, offset_bits, offset_refs, limit_bits, limit_refs)
    hash_str = source.hash.hex()
    offset = offset_bits

    instructions = [
        process_instruction(op, source, on_cell_reference)
        for op in opcodes
    ]

    if not instructions:
        return create_block([], hash_str, offset, 0)

    last_instruction = instructions[-1]
    length = last_instruction.offset + last_instruction.length

    return create_block(instructions, hash_str, offset, length)


def process_instruction(
    op: DecompiledInstruction,
    source: Cell,
    on_cell_reference: Optional[Callable[[Cell], None]] = None
) -> InstructionNode:
    """
    Process an instruction to correctly handle references, calls and operands.

    Args:
        op: The decompiled instruction
        source: The source cell
        on_cell_reference: Callback for cell references

    Returns:
        Processed InstructionNode
    """
    opcode = op.op
    opcode_name = opcode.definition['mnemonic']

    if opcode_name == 'CALLREF':
        return process_callref(op, source, on_cell_reference)
    elif opcode_name in ('CALLDICT', 'CALLDICT_LONG', 'JMPDICT'):
        return process_calldict(op)

    return process_default_instruction(op, source, on_cell_reference)


def process_callref(
    op: DecompiledInstruction,
    source: Cell,
    on_cell_reference: Optional[Callable[[Cell], None]] = None
) -> InstructionNode:
    """
    Process a CALLREF instruction.

    Args:
        op: The decompiled instruction
        source: The source cell
        on_cell_reference: Callback for cell references

    Returns:
        Processed InstructionNode
    """
    opcode = op.op

    # Find the 'c' operand (cell reference)
    operand = None
    for op_val in opcode.operands:
        if op_val.definition['name'] == 'c' and op_val.type == 'ref':
            operand = op_val
            break

    if operand is None:
        raise ValueError(f"CALLREF operand 'c' not found or wrong type")

    # If we want to extract to separate function
    if on_cell_reference:
        on_cell_reference(operand.value)
        return create_instruction(
            PSEUDO_INLINECALLDICT,
            [ReferenceNode(type='reference', hash=operand.value.hash.hex())],
            op.offset,
            op.length,
            op.hash
        )

    # Otherwise, inline the code
    block = disassemble_and_process(
        operand.value,
        offset_bits=0,
        offset_refs=0,
        on_cell_reference=on_cell_reference
    )

    # Mark as cell block
    block_with_cell = create_block(
        block.instructions,
        block.hash,
        block.offset,
        block.length,
        cell=True
    )

    return create_instruction(
        opcode,
        [block_with_cell],
        op.offset,
        op.length,
        op.hash
    )


def process_calldict(op: DecompiledInstruction) -> InstructionNode:
    """
    Process CALLDICT, CALLDICT_LONG, or JMPDICT instruction.

    Args:
        op: The decompiled instruction

    Returns:
        Processed InstructionNode
    """
    opcode = op.op

    # Find the 'n' operand (method ID)
    operand = None
    for op_val in opcode.operands:
        if op_val.definition['name'] == 'n' and op_val.type == 'numeric':
            operand = op_val
            break

    if operand is None:
        raise ValueError(f"CALLDICT operand 'n' not found or wrong type")

    return create_instruction(
        opcode,
        [MethodReferenceNode(type='method_reference', method_id=operand.value)],
        op.offset,
        op.length,
        op.hash
    )


def process_default_instruction(
    op: DecompiledInstruction,
    source: Cell,
    on_cell_reference: Optional[Callable[[Cell], None]] = None
) -> InstructionNode:
    """
    Process all other instructions.

    Args:
        op: The decompiled instruction
        source: The source cell
        on_cell_reference: Callback for cell references

    Returns:
        Processed InstructionNode
    """
    opcode = op.op
    operands = []

    for operand in opcode.operands:
        if operand.type == 'numeric':
            operands.append(process_numeric_operand(operand))
        elif operand.type == 'bigint':
            operands.append(ScalarNode(type='scalar', value=operand.value))
        elif operand.type in ('ref', 'subslice'):
            operands.append(process_ref_or_slice_operand(operand, source, on_cell_reference))
        else:
            raise ValueError(f"Unknown operand type: {operand.type}")

    return create_instruction(opcode, operands, op.offset, op.length, op.hash)


def process_numeric_operand(operand):
    """Process a numeric operand into appropriate node type."""
    from ..ast.ast import StackEntryNode, ControlRegisterNode, GlobalVariableNode, ScalarNode

    display_hints = operand.definition.get('display_hints', [])

    # Calculate display number with hints
    add_hint = next((h.get('value', 0) for h in display_hints if h.get('type') == 'add'), 0)
    display_number = get_display_number(operand, add_hint, display_hints)

    # Check hint type
    if has_hint(display_hints, 'stack'):
        return StackEntryNode(type='stack_entry', value=display_number)
    elif has_hint(display_hints, 'register'):
        return ControlRegisterNode(type='control_register', value=display_number)
    elif has_hint(display_hints, 'global'):
        return GlobalVariableNode(type='global_variable', value=display_number)
    else:
        return ScalarNode(type='scalar', value=display_number)


def process_ref_or_slice_operand(operand, source, on_cell_reference):
    """Process reference or slice operands."""
    from ..ast.ast import ScalarNode

    if operand.type == 'ref':
        return ScalarNode(type='scalar', value=operand.value)
    else:  # subslice
        return ScalarNode(type='scalar', value=operand.value)


def get_display_number(operand, add: int, display_hints: List[Dict]) -> int:
    """Calculate the display number for an operand."""
    value = operand.value

    # Apply add hint
    value += add

    # Apply negate hint
    if has_hint(display_hints, 'negate'):
        value = -value

    return value


def has_hint(hints: List[Dict], hint_type: str) -> bool:
    """Check if a hint type exists in the hints list."""
    return any(h.get('type') == hint_type for h in hints)


def disassemble_root(source: Cell, compute_refs: bool = True) -> ProgramNode:
    """
    Disassemble the root cell into a program.

    This function unpacks the dictionary to extract methods and procedures.

    Args:
        source: The root cell to disassemble
        compute_refs: Whether to deduplicate refs into separate functions

    Returns:
        ProgramNode representing the complete program
    """
    # TODO: Implement dictionary unpacking for methods
    # For now, just disassemble as a raw root
    block = disassemble_raw_root(source)

    return create_program(
        top_level_instructions=block.instructions,
        methods=[],
        procedures=[],
        with_refs=compute_refs
    )


def disassemble_raw_root(source: Cell) -> BlockNode:
    """
    Disassemble a cell without any additional unpacking.

    Args:
        source: The cell to disassemble

    Returns:
        BlockNode containing all instructions
    """
    return disassemble_and_process(source)
