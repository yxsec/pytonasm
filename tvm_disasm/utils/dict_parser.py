"""
Dictionary parsing helpers mirroring @ton/core behaviour.
"""
import math
from typing import Callable, Dict, Tuple

from pytoniq_core import Cell

from .ton_slice import TonSlice


def parse_code_dictionary(
    dict_cell: Cell,
    key_bits: int,
    extractor: Callable[[TonSlice], Tuple[Cell, int]],
) -> Dict[int, Tuple[Cell, int]]:
    """
    Parse dictionary storing code cells into key -> (cell, offset) map.
    """
    if dict_cell is None:
        return {}

    root_slice = TonSlice.from_cell(dict_cell)
    if root_slice.remaining_bits == 0 and root_slice.remaining_refs == 0:
        return {}

    result: Dict[int, Tuple[Cell, int]] = {}

    def read_unary_length(slice_obj: TonSlice) -> int:
        length = 0
        while slice_obj.load_bit() == 1:
            length += 1
        return length

    def parse_node(prefix_bits: int, remaining: int, slice_obj: TonSlice) -> None:
        if remaining < 0:
            raise ValueError("Malformed dictionary: negative remaining bits")

        prefix_added = 0
        prefix_value = prefix_bits

        lb0 = slice_obj.load_bit()
        if lb0 == 0:
            prefix_added = read_unary_length(slice_obj)
            for _ in range(prefix_added):
                prefix_value = (prefix_value << 1) | slice_obj.load_bit()
        else:
            lb1 = slice_obj.load_bit()
            log_bits = 0 if remaining + 1 <= 1 else math.ceil(math.log2(remaining + 1))
            if lb1 == 0:
                prefix_added = slice_obj.load_uint(log_bits)
                for _ in range(prefix_added):
                    prefix_value = (prefix_value << 1) | slice_obj.load_bit()
            else:
                repeated_bit = slice_obj.load_bit()
                prefix_added = slice_obj.load_uint(log_bits)
                for _ in range(prefix_added):
                    prefix_value = (prefix_value << 1) | repeated_bit

        remaining_after_label = remaining - prefix_added
        if remaining_after_label < 0:
            raise ValueError("Malformed dictionary: label exceeds key size")

        if remaining_after_label == 0:
            cell, offset = extractor(slice_obj.clone())
            result[prefix_value] = (cell, offset)
            return

        left_slice = slice_obj.load_ref()
        right_slice = slice_obj.load_ref()

        parse_node(prefix_value << 1, remaining_after_label - 1, left_slice)
        parse_node((prefix_value << 1) | 1, remaining_after_label - 1, right_slice)

    parse_node(0, key_bits, root_slice)
    return result


def code_cell_extractor(slice_obj: TonSlice) -> Tuple[Cell, int]:
    """
    Extract code cell and bit offset from slice, matching createCodeCell.parse.
    """
    clone = slice_obj.clone(reset=True)
    cell = clone.to_cell()
    offset = slice_obj.offset_bits
    return cell, offset
