"""
Utility to create limited slice similar to opcode's subslice helper.
"""
from pytoniq_core import Cell, begin_cell


def create_subslice(
    cell: Cell,
    offset_bits: int,
    offset_refs: int,
    bits_limit: int,
    refs_limit: int,
):
    """
    Create a slice window on top of cell constrained by offsets and limits.
    """
    source_slice = cell.begin_parse()
    builder = begin_cell()

    total_bits = offset_bits + bits_limit
    if total_bits > 0:
        bits = source_slice.load_bits(total_bits)
        builder.store_bits(bits)

    total_refs = offset_refs + refs_limit
    for _ in range(total_refs):
        builder.store_ref(source_slice.load_ref())

    limited_slice = builder.end_cell().begin_parse()

    if offset_bits > 0:
        limited_slice.skip_bits(offset_bits)
    if offset_refs > 0:
        for _ in range(offset_refs):
            limited_slice.load_ref()

    return limited_slice
