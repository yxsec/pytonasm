"""
Prefix matcher for identifying TVM opcodes from bytecode.
"""
import json
import os
from typing import Dict, Any
from pytoniq_core import Slice
from .binutils import prefix_to_bin


def bits_to_bitstring(bits: 'TvmBitarray') -> str:
    """Convert TvmBitarray to bit string ('0' and '1' chars)."""
    result = ''
    for i in range(len(bits)):
        result += '1' if bits[i] else '0'
    return result


class PrefixMatcher:
    """
    Matches bytecode prefixes to TVM instructions.

    Uses the cp0.json specification to build a map of instruction prefixes
    and efficiently matches them against bytecode slices.
    """

    def __init__(self):
        """Initialize the prefix matcher with cp0 instruction set."""
        # Load the instruction specification
        spec_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'spec',
            'cp0.json'
        )

        with open(spec_path, 'r') as f:
            cp0 = json.load(f)

        # Build a map of prefix (bit string) -> instruction
        self.instructions: Dict[str, Dict[str, Any]] = {}

        for inst in cp0['instructions']:
            prefix_bits = prefix_to_bin(inst['bytecode']['prefix'])
            self.instructions[prefix_bits] = inst

        # Calculate the longest prefix length for optimization
        self.longest_prefix_length = max(
            len(prefix_to_bin(inst['bytecode']['prefix']))
            for inst in cp0['instructions']
        )

    def load_prefix(self, slice_obj: Slice) -> Dict[str, Any]:
        """
        Match and load an instruction from a bytecode slice.

        Tries to match increasingly longer prefixes until an instruction is found.
        Handles range checks for variable-length opcodes.

        Args:
            slice_obj: The bytecode slice to read from

        Returns:
            The matched instruction definition

        Raises:
            ValueError: If no matching instruction is found
        """
        for bits in range(1, self.longest_prefix_length + 1):
            if slice_obj.remaining_bits < bits:
                raise ValueError(f"Prefix not found, remaining bits: {slice_obj.remaining_bits}")

            # Preload bits without consuming them
            prefix_bitarray = slice_obj.preload_bits(bits)
            prefix_str = bits_to_bitstring(prefix_bitarray)
            instruction = self.instructions.get(prefix_str)

            if instruction is None:
                continue

            # Check operand range if specified
            range_check = instruction['bytecode'].get('operands_range_check')
            if range_check is not None:
                check_len = range_check['length']

                if slice_obj.remaining_bits < bits + check_len:
                    continue

                # Clone slice and skip prefix to read operands
                temp_slice = slice_obj.copy()
                temp_slice.skip_bits(bits)
                operands = temp_slice.load_uint(check_len)

                # Check if operands are in valid range
                if operands < range_check['from'] or operands > range_check['to']:
                    continue

            # Match found, consume the prefix bits
            slice_obj.skip_bits(bits)
            return instruction

        raise ValueError(f"Prefix not found, remaining bits: {slice_obj.remaining_bits}")
