"""
Binary utilities for handling TVM bytecode prefixes.
"""
from pytoniq_core import TvmBitarray


def prefix_to_bin(prefix: str) -> str:
    """
    Convert a hex prefix string to a bit string.

    Handles completion tags (trailing underscore) which indicate the last
    set bit should be removed.

    Args:
        prefix: Hex string, possibly with trailing '_' for completion tag

    Returns:
        Bit string representation of the prefix (as '0' and '1' characters)
    """
    completion_tag = prefix.endswith("_")
    if completion_tag:
        prefix = prefix[:-1]

    # Pad to even length for hex parsing
    pad_length = len(prefix) % 2
    padded_hex = prefix + "0" * pad_length

    # Convert hex to binary string
    binary_str = bin(int(padded_hex, 16))[2:].zfill(len(padded_hex) * 4)

    # Remove padding bits
    if pad_length > 0:
        binary_str = binary_str[:-(pad_length * 4)]

    if completion_tag:
        return remove_completion_tag(binary_str)

    return binary_str


def remove_completion_tag(bits: str) -> str:
    """
    Remove the completion tag from a bit string.

    The completion tag is the last set bit in the string. This function
    finds it and removes it along with all trailing bits.

    Args:
        bits: Bit string with completion tag

    Returns:
        Bit string with completion tag removed

    Raises:
        ValueError: If no completion tag is found
    """
    # Find the last set bit ('1')
    last_set_bit_index = -1
    for i in range(len(bits) - 1, -1, -1):
        if bits[i] == '1':
            last_set_bit_index = i
            break

    if last_set_bit_index == -1:
        raise ValueError("No completion tag found")

    # Return substring up to (but not including) the completion tag
    return bits[:last_set_bit_index]
