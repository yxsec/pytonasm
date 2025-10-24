"""
Utility slice implementation mirroring TON JS Slice behavior.
"""
from dataclasses import dataclass
from typing import List

from pytoniq_core import Cell, begin_cell


@dataclass
class TonSlice:
    """Lightweight slice wrapper for dictionary parsing with offset tracking."""

    _bits: str
    _refs: List[Cell]
    _offset_bits: int = 0
    _offset_refs: int = 0

    @classmethod
    def from_cell(cls, cell: Cell) -> "TonSlice":
        """Create a slice from a Cell."""
        bits = cell.bits.to01()
        refs = list(cell.refs)
        return cls(bits, refs, 0, 0)

    @property
    def offset_bits(self) -> int:
        return self._offset_bits

    @property
    def offset_refs(self) -> int:
        return self._offset_refs

    @property
    def remaining_bits(self) -> int:
        return len(self._bits) - self._offset_bits

    @property
    def remaining_refs(self) -> int:
        return len(self._refs) - self._offset_refs

    def clone(self, reset: bool = False) -> "TonSlice":
        """Clone slice optionally resetting offsets."""
        if reset:
            return TonSlice(self._bits, self._refs, 0, 0)
        return TonSlice(self._bits, self._refs, self._offset_bits, self._offset_refs)

    def load_bit(self) -> int:
        if self._offset_bits >= len(self._bits):
            raise ValueError("Slice underflow while reading bit")
        bit = 1 if self._bits[self._offset_bits] == "1" else 0
        self._offset_bits += 1
        return bit

    def load_uint(self, size: int) -> int:
        if size == 0:
            return 0
        if self._offset_bits + size > len(self._bits):
            raise ValueError("Slice underflow while reading uint")
        segment = self._bits[self._offset_bits : self._offset_bits + size]
        self._offset_bits += size
        return int(segment, 2)

    def load_bits(self, size: int) -> str:
        if self._offset_bits + size > len(self._bits):
            raise ValueError("Slice underflow while reading bits")
        segment = self._bits[self._offset_bits : self._offset_bits + size]
        self._offset_bits += size
        return segment

    def load_ref(self) -> "TonSlice":
        if self._offset_refs >= len(self._refs):
            raise ValueError("Slice underflow while reading ref")
        cell = self._refs[self._offset_refs]
        self._offset_refs += 1
        return TonSlice.from_cell(cell)

    def to_cell(self) -> Cell:
        """Materialise remaining slice as Cell."""
        builder = begin_cell()
        bits = self._bits[self._offset_bits :]
        if bits:
            builder.store_uint(int(bits, 2), len(bits))
        for ref in self._refs[self._offset_refs :]:
            builder.store_ref(ref)
        return builder.end_cell()

    def as_cell(self) -> Cell:
        """Return full cell regardless of current offset."""
        return self.clone(reset=True).to_cell()
