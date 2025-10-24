"""
Binary utilities for handling TVM bytecode prefixes.
"""
from typing import Union

from pytoniq_core import TvmBitarray


def prefix_to_bin(prefix: str) -> str:
    """
    Convert a hex prefix string to a bit string, handling completion tags.
    """
    completion_tag = prefix.endswith("_")
    if completion_tag:
        prefix = prefix[:-1]

    pad_length = len(prefix) % 2
    padded_hex = prefix + "0" * pad_length

    if padded_hex:
        value = int(padded_hex, 16)
        binary_str = bin(value)[2:].zfill(len(padded_hex) * 4)
    else:
        binary_str = ""

    if pad_length > 0:
        binary_str = binary_str[:-(pad_length * 4)]

    if completion_tag:
        binary_str = remove_completion_tag(binary_str)

    return binary_str


def remove_completion_tag(bits: Union[str, TvmBitarray]) -> Union[str, TvmBitarray]:
    """
    Remove the completion tag from a bit sequence.
    """
    if isinstance(bits, TvmBitarray):
        idx = len(bits) - 1
        while idx >= 0 and not bits[idx]:
            idx -= 1
        if idx < 0:
            raise ValueError("No completion tag found")
        return bits[:idx]

    last_set_bit_index = -1
    for i in range(len(bits) - 1, -1, -1):
        if bits[i] == "1":
            last_set_bit_index = i
            break
    if last_set_bit_index == -1:
        raise ValueError("No completion tag found")
    return bits[:last_set_bit_index]
