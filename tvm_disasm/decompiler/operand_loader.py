"""
Operand loader for decoding TVM instruction operands.
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Union
from pytoniq_core import Cell, Slice, Builder, TvmBitarray
from ..utils.prefix_matcher import PrefixMatcher, bits_to_bitstring
from ..utils.binutils import remove_completion_tag


# Global prefix matcher instance
prefix_matcher = PrefixMatcher()


class TrackedSlice:
    """Wrapper for Slice that tracks bit and ref offsets."""

    def __init__(self, slice_obj: Slice, initial_bits: int, initial_refs: int):
        self.slice = slice_obj
        self.initial_bits = initial_bits
        self.initial_refs = initial_refs

    @property
    def offset_bits(self) -> int:
        return self.initial_bits - self.slice.remaining_bits

    @property
    def offset_refs(self) -> int:
        return self.initial_refs - self.slice.remaining_refs

    @property
    def remaining_bits(self) -> int:
        return self.slice.remaining_bits

    @property
    def remaining_refs(self) -> int:
        return self.slice.remaining_refs

    def copy(self) -> 'TrackedSlice':
        return TrackedSlice(
            self.slice.copy(),
            self.initial_bits,
            self.initial_refs
        )

    def load_bits(self, bits: int) -> TvmBitarray:
        return self.slice.load_bits(bits)

    def load_uint(self, bits: int) -> int:
        return self.slice.load_uint(bits)

    def load_int(self, bits: int) -> int:
        return self.slice.load_int(bits)

    def load_ref(self) -> Cell:
        return self.slice.load_ref()

    def skip_bits(self, bits: int):
        self.slice.skip_bits(bits)


@dataclass
class NumericValue:
    """Represents a numeric operand value"""
    type: str
    definition: Dict[str, Any]
    value: int
    bitcode: str  # Binary string representation


@dataclass
class BigIntValue:
    """Represents a big integer operand value"""
    type: str
    definition: Dict[str, Any]
    value: int
    bitcode: str  # Binary string representation


@dataclass
class RefValue:
    """Represents a reference operand value"""
    type: str
    definition: Dict[str, Any]
    value: Cell
    bitcode: str  # Binary string representation


@dataclass
class SliceValue:
    """Represents a subslice operand value"""
    type: str
    definition: Dict[str, Any]
    value: Cell
    source: Cell
    offset_bits: int
    offset_refs: int
    limit_bits: int
    limit_refs: int


OperandValue = Union[NumericValue, BigIntValue, RefValue, SliceValue]


@dataclass
class DecodedInstruction:
    """Represents a decoded TVM instruction with its operands"""
    definition: Dict[str, Any]
    operands: List[OperandValue]


def decode_instruction(source: Cell, slice_obj: Union[Slice, TrackedSlice]) -> DecodedInstruction:
    """
    Decode a single instruction from a bytecode slice.

    Args:
        source: The source cell containing the bytecode
        slice_obj: The slice to read from (can be Slice or TrackedSlice)

    Returns:
        DecodedInstruction with opcode definition and parsed operands
    """
    # Convert to TrackedSlice if needed
    if isinstance(slice_obj, Slice):
        tracked = TrackedSlice(
            slice_obj,
            slice_obj.remaining_bits,
            slice_obj.remaining_refs
        )
    else:
        tracked = slice_obj

    definition = prefix_matcher.load_prefix(tracked.slice)
    operands = parse_operands(source, tracked, definition)

    return DecodedInstruction(
        definition=definition,
        operands=operands
    )


def parse_operands(
    source: Cell,
    slice_obj: TrackedSlice,
    instruction: Dict[str, Any]
) -> List[OperandValue]:
    """
    Parse all operands for an instruction.

    Args:
        source: The source cell
        slice_obj: The tracked slice to read from
        instruction: The instruction definition

    Returns:
        List of parsed operand values

    Raises:
        ValueError: If operand parsing fails
    """
    operands = []

    for operand_def in instruction['bytecode']['operands']:
        try:
            operands.append(parse_operand(source, operand_def, slice_obj))
        except Exception as e:
            raise ValueError(
                f"Bad operand {operand_def['name']} for instruction {instruction['mnemonic']}"
            ) from e

    return operands


def parse_operand(
    source: Cell,
    operand_def: Dict[str, Any],
    slice_obj: TrackedSlice
) -> OperandValue:
    """
    Parse a single operand.

    Args:
        source: The source cell
        operand_def: The operand definition
        slice_obj: The tracked slice to read from

    Returns:
        Parsed operand value

    Raises:
        ValueError: If operand type is unknown
    """
    operand_type = operand_def['type']

    if operand_type == 'uint':
        # Clone to get raw bits before consuming
        raw = slice_obj.copy().load_bits(operand_def['size'])
        value = slice_obj.load_uint(operand_def['size'])

        return NumericValue(
            type='numeric',
            definition=operand_def,
            value=value,
            bitcode=bits_to_bitstring(raw)
        )

    elif operand_type == 'int':
        raw = slice_obj.copy().load_bits(operand_def['size'])
        value = slice_obj.load_int(operand_def['size'])

        return NumericValue(
            type='numeric',
            definition=operand_def,
            value=value,
            bitcode=bits_to_bitstring(raw)
        )

    elif operand_type == 'ref':
        # For refs, the bitcode is the cell's bits
        raw_cell = slice_obj.copy().load_ref()
        value = slice_obj.load_ref()

        return RefValue(
            type='ref',
            definition=operand_def,
            value=value,
            bitcode=bits_to_bitstring(raw_cell.bits)
        )

    elif operand_type == 'pushint_long':
        cloned = slice_obj.copy()
        prefix = slice_obj.load_uint(5)
        length = 8 * prefix + 19
        raw = cloned.load_bits(5 + length)
        value = slice_obj.load_int(length)

        return BigIntValue(
            type='bigint',
            definition=operand_def,
            value=value,
            bitcode=bits_to_bitstring(raw)
        )

    else:
        # Handle subslice type
        refs_add = operand_def.get('refs_add', 0)
        refs_length_var_size = operand_def.get('refs_length_var_size', 0)
        bits_padding = operand_def.get('bits_padding', 0)
        bits_length_var_size = operand_def.get('bits_length_var_size', 0)
        completion_tag = operand_def.get('completion_tag', False)

        ref_length = refs_add + (
            slice_obj.load_uint(refs_length_var_size) if refs_length_var_size else 0
        )
        bit_length = bits_padding + (
            slice_obj.load_uint(bits_length_var_size) * 8 if bits_length_var_size else 0
        )

        offset_bits = slice_obj.offset_bits
        offset_refs = slice_obj.offset_refs

        loaded_bits = slice_obj.load_bits(bit_length)
        bits_array = remove_completion_tag(loaded_bits) if completion_tag else loaded_bits

        from pytoniq_core import begin_cell
        builder = begin_cell()
        if bits_array:
            builder.store_bits(bits_array)

        for _ in range(ref_length):
            builder.store_ref(slice_obj.load_ref())

        return SliceValue(
            type='subslice',
            definition=operand_def,
            value=builder.end_cell(),
            source=source,
            offset_bits=offset_bits,
            offset_refs=offset_refs,
            limit_bits=bit_length,
            limit_refs=ref_length
        )
