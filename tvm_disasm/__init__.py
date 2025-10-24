"""
TVM Disassembler - Python implementation of TON Virtual Machine bytecode decompiler.

This package provides tools to disassemble TVM bytecode (BoC files) into
human-readable Fift assembly code.
"""

from .decompiler import (
    disassemble,
    disassemble_root,
    disassemble_raw_root,
    disassemble_and_process,
    decode_instruction,
    parse_operands,
    DecodedInstruction,
)
from .printer import AssemblyWriter, InstructionWriter
from .ast import *

__version__ = "0.1.0"

__all__ = [
    # Decompiler functions
    'disassemble',
    'disassemble_root',
    'disassemble_raw_root',
    'disassemble_and_process',
    'decode_instruction',
    'parse_operands',
    'DecodedInstruction',

    # Writers
    'AssemblyWriter',
    'InstructionWriter',

    # AST nodes
    'ControlRegisterNode',
    'StackEntryNode',
    'GlobalVariableNode',
    'ScalarNode',
    'ReferenceNode',
    'MethodReferenceNode',
    'InstructionNode',
    'BlockNode',
    'MethodNode',
    'ProcedureNode',
    'ProgramNode',
]
