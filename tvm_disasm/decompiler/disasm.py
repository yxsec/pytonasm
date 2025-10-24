"""
Core disassembler for TVM bytecode.
"""
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from pytoniq_core import Cell

from .operand_loader import DecodedInstruction, decode_instruction
from ..ast.ast import (
    BlockNode,
    InstructionNode,
    MethodNode,
    MethodReferenceNode,
    ProcedureNode,
    ProgramNode,
    ReferenceNode,
    ScalarNode,
    create_block,
    create_instruction,
    create_method,
    create_procedure,
    create_program,
)
from ..utils.dict_parser import code_cell_extractor, parse_code_dictionary

sys.setrecursionlimit(max(sys.getrecursionlimit(), 100000))

_BLOCK_CACHE: Dict[Tuple[str, int, int, int, int], BlockNode] = {}


@dataclass
class DecompiledInstruction:
    """Represents a decompiled instruction with metadata"""
    op: DecodedInstruction
    hash: str
    offset: int
    length: int


# Pseudo instruction for INLINECALLDICT (Fift opcode, not TVM)
PSEUDO_INLINECALLDICT = DecodedInstruction(
    definition={
        "mnemonic": "INLINECALLDICT",
        "doc": {
            "fift": "INLINECALLDICT",
            "description": "Inline call to dictionary method (pseudo-opcode for decompiler)",
        },
        "bytecode": {
            "prefix": "",
            "operands": [],
        },
    },
    operands=[],
)


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
    bits_limit = limit_bits if limit_bits is not None else len(source.bits) - offset_bits
    refs_limit = limit_refs if limit_refs is not None else len(source.refs) - offset_refs

    slice_obj = source.begin_parse()

    initial_bits = slice_obj.remaining_bits
    initial_refs = slice_obj.remaining_refs

    if offset_bits > 0:
        slice_obj.skip_bits(offset_bits)
    if offset_refs > 0:
        for _ in range(offset_refs):
            slice_obj.load_ref()

    instructions: List[DecompiledInstruction] = []
    hash_str = source.hash.hex()

    bits_processed = 0
    while slice_obj.remaining_bits > 0 and bits_processed < bits_limit:
        opcode_offset = initial_bits - slice_obj.remaining_bits
        opcode = decode_instruction(source, slice_obj)
        opcode_length = (initial_bits - slice_obj.remaining_bits) - opcode_offset

        instructions.append(
            DecompiledInstruction(
                op=opcode,
                hash=hash_str,
                offset=opcode_offset,
                length=opcode_length,
            )
        )

        bits_processed = (initial_bits - slice_obj.remaining_bits) - offset_bits

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
    normalized_bits = limit_bits if limit_bits is not None else max(0, len(source.bits) - offset_bits)
    normalized_refs = limit_refs if limit_refs is not None else max(0, len(source.refs) - offset_refs)

    cache_key = None
    if on_cell_reference is None:
        cache_key = (
            source.hash.hex(),
            offset_bits,
            offset_refs,
            normalized_bits,
            normalized_refs,
        )
        cached = _BLOCK_CACHE.get(cache_key)
        if cached is not None:
            return cached

    opcodes = disassemble(source, offset_bits, offset_refs, normalized_bits, normalized_refs)
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

    block = create_block(instructions, hash_str, offset, length)

    if cache_key is not None:
        _BLOCK_CACHE[cache_key] = block

    return block


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
    on_cell_reference: Optional[Callable[[Cell], None]] = None,
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
            operands.append(
                process_ref_or_slice_operand(opcode, operand, source, on_cell_reference)
            )
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


def process_ref_or_slice_operand(
    opcode: DecodedInstruction,
    operand,
    source: Cell,
    on_cell_reference: Optional[Callable[[Cell], None]] = None,
):
    """Process reference or slice operands."""
    display_hints = operand.definition.get('display_hints', [])
    opcode_name = opcode.definition['mnemonic']

    is_continuation = (
        has_hint(display_hints, 'continuation')
        or opcode_name in {'PUSHCONT', 'PUSHCONT_SHORT'}
    )

    if is_continuation:
        if operand.type == 'ref':
            block = disassemble_and_process(
                operand.value,
                offset_bits=0,
                offset_refs=0,
                on_cell_reference=on_cell_reference,
            )
            return create_block(
                block.instructions,
                block.hash,
                block.offset,
                block.length,
                cell=True,
            )

        if operand.type == 'subslice':
            return disassemble_and_process(
                operand.value,
                offset_bits=0,
                offset_refs=0,
                on_cell_reference=on_cell_reference,
            )

    return ScalarNode(type='scalar', value=getattr(operand, "value", None))


def get_display_number(operand, add: int, display_hints: List[Dict]) -> int:
    """Calculate the display number for an operand."""
    value = operand.value

    # Apply add hint
    value += add

    if has_hint(display_hints, 'pushint4'):
        value = value - 16 if value > 10 else value

    if has_hint(display_hints, 'optional_nargs'):
        value = -1 if value == 15 else value

    if has_hint(display_hints, 'plduz'):
        value = 32 * (value + 1)

    # Apply negate hint
    if has_hint(display_hints, 'negate'):
        value = -value

    return value


def has_hint(hints: List[Dict], hint_type: str) -> bool:
    """Check if a hint type exists in the hints list."""
    return any(h.get('type') == hint_type for h in hints)


def disassemble_root(source: Cell, compute_refs: bool = True) -> ProgramNode:
    """
    Disassemble the root cell into a program with dictionary unpacking.
    """
    opcodes = disassemble(source)
    top_level_instructions = [
        process_instruction(op, source, None) for op in opcodes
    ]

    root_methods = find_root_methods(opcodes)
    dict_opcode = find_dict_opcode(opcodes)

    if dict_opcode is None:
        return create_program(
            top_level_instructions=top_level_instructions,
            methods=root_methods,
            procedures=[],
            with_refs=compute_refs,
        )

    procedures, methods = deserialize_dict(
        dict_opcode.op.operands,
        compute_refs=compute_refs,
    )

    merged_methods = root_methods + methods

    return create_program(
        top_level_instructions=top_level_instructions,
        methods=merged_methods,
        procedures=procedures,
        with_refs=compute_refs,
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


def find_dict_opcode(opcodes: List[DecompiledInstruction]) -> Optional[DecompiledInstruction]:
    """Find the DICTPUSHCONST instruction in the opcode list."""
    for opcode in opcodes:
        if opcode.op.definition['mnemonic'] == 'DICTPUSHCONST':
            return opcode
    return None


def find_root_methods(opcodes: List[DecompiledInstruction]) -> List[MethodNode]:
    """Extract implicit recv methods from known PUSHCONT locations."""
    methods: List[MethodNode] = []
    mappings = {2: 0, 6: -1}

    for index, method_id in mappings.items():
        if index >= len(opcodes):
            continue

        candidate = opcodes[index]
        if candidate.op.definition['mnemonic'] != 'PUSHCONT':
            continue

        cont_operand = candidate.op.operands[0] if candidate.op.operands else None
        if cont_operand is None or cont_operand.type != 'subslice':
            continue

        block = disassemble_raw_root(cont_operand.value)
        methods.append(
            create_method(
                method_id=method_id,
                body=block,
                hash_str=block.hash,
                offset=block.offset,
            )
        )

    return methods


def deserialize_dict(
    operands: List,
    compute_refs: bool,
) -> Tuple[List[ProcedureNode], List[MethodNode]]:
    """Deserialize dictionary operand into procedures and methods."""
    dict_key = next(
        (operand for operand in operands if operand.definition['name'] == 'n'),
        None,
    )
    dict_cell_operand = next(
        (operand for operand in operands if operand.definition['name'] == 'd'),
        None,
    )

    if (
        dict_key is None
        or dict_cell_operand is None
        or dict_key.type != 'numeric'
        or dict_cell_operand.type != 'ref'
    ):
        raise ValueError("DICTPUSHCONST operands are malformed")

    key_length = dict_key.value
    dict_cell = dict_cell_operand.value
    entries = parse_code_dictionary(dict_cell, key_length, code_cell_extractor)
    if not entries:
        return [], []

    registered_cells: Dict[str, str] = {}
    procedures: List[ProcedureNode] = []

    def extract_referenced_cell(cell: Cell) -> None:
        cell_hash = cell.hash.hex()
        if cell_hash in registered_cells:
            return

        registered_cells[cell_hash] = f"?fun_ref_{cell_hash[:16]}"
        block = disassemble_and_process(
            cell,
            offset_bits=0,
            offset_refs=0,
            on_cell_reference=extract_referenced_cell if compute_refs else None,
        )
        procedures.append(create_procedure(cell_hash, block))

    methods: List[MethodNode] = []

    for method_id in sorted(entries.keys()):
        code_cell, offset_bits = entries[method_id]

        block = disassemble_and_process(
            code_cell,
            offset_bits=offset_bits,
            offset_refs=0,
            limit_bits=None,
            limit_refs=None,
            on_cell_reference=extract_referenced_cell if compute_refs else None,
        )

        methods.append(
            create_method(
                method_id=method_id,
                body=block,
                hash_str=code_cell.hash.hex(),
                offset=offset_bits,
            )
        )

    return procedures, methods
