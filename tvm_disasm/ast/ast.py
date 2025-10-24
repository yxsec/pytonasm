"""
AST (Abstract Syntax Tree) definitions for TVM bytecode decompilation.
"""
from dataclasses import dataclass
from typing import Union, List, Any
from pytoniq_core import Cell


@dataclass(frozen=True)
class ControlRegisterNode:
    """Represents a control register (c0-c7)"""
    type: str = "control_register"
    value: int = 0


@dataclass(frozen=True)
class StackEntryNode:
    """Represents a stack entry (s0, s1, etc.)"""
    type: str = "stack_entry"
    value: int = 0


@dataclass(frozen=True)
class GlobalVariableNode:
    """Represents a global variable"""
    type: str = "global_variable"
    value: int = 0


@dataclass(frozen=True)
class ScalarNode:
    """Represents a scalar value (number, string, bigint, or Cell)"""
    type: str = "scalar"
    value: Union[int, str, Cell] = 0


@dataclass(frozen=True)
class ReferenceNode:
    """Represents a reference to a cell by hash"""
    type: str = "reference"
    hash: str = ""


@dataclass(frozen=True)
class MethodReferenceNode:
    """Represents a reference to a method by ID"""
    type: str = "method_reference"
    method_id: int = 0


# Union type for all possible instruction arguments
InstructionArgument = Union[
    ScalarNode,
    'BlockNode',
    ReferenceNode,
    StackEntryNode,
    ControlRegisterNode,
    GlobalVariableNode,
    MethodReferenceNode
]


@dataclass(frozen=True)
class InstructionNode:
    """Represents a single TVM instruction"""
    opcode: Any  # DecodedInstruction
    type: str = "instruction"
    arguments: List[InstructionArgument] = None
    offset: int = 0
    length: int = 0
    hash: str = ""

    def __post_init__(self):
        if self.arguments is None:
            object.__setattr__(self, 'arguments', [])


@dataclass(frozen=True)
class BlockNode:
    """Represents a block of instructions"""
    type: str = "block"
    instructions: List[InstructionNode] = None
    hash: str = ""
    offset: int = 0
    length: int = 0
    cell: bool = False

    def __post_init__(self):
        if self.instructions is None:
            object.__setattr__(self, 'instructions', [])


@dataclass(frozen=True)
class MethodNode:
    """Represents a method (function with ID)"""
    type: str = "method"
    id: int = 0
    body: BlockNode = None
    hash: str = ""
    offset: int = 0


@dataclass(frozen=True)
class ProcedureNode:
    """Represents a procedure (function without ID)"""
    type: str = "procedure"
    hash: str = ""
    body: BlockNode = None


@dataclass(frozen=True)
class ProgramNode:
    """Represents a complete TVM program"""
    type: str = "program"
    top_level_instructions: List[InstructionNode] = None
    methods: List[MethodNode] = None
    procedures: List[ProcedureNode] = None
    with_refs: bool = False

    def __post_init__(self):
        if self.top_level_instructions is None:
            object.__setattr__(self, 'top_level_instructions', [])
        if self.methods is None:
            object.__setattr__(self, 'methods', [])
        if self.procedures is None:
            object.__setattr__(self, 'procedures', [])


# Helper functions to create AST nodes
def create_instruction(
    opcode: Any,
    arguments: List[InstructionArgument],
    offset: int,
    length: int,
    hash_str: str
) -> InstructionNode:
    """Create an InstructionNode"""
    return InstructionNode(
        type="instruction",
        opcode=opcode,
        arguments=arguments or [],
        offset=offset,
        length=length,
        hash=hash_str
    )


def create_block(
    instructions: List[InstructionNode],
    hash_str: str,
    offset: int,
    length: int,
    cell: bool = False
) -> BlockNode:
    """Create a BlockNode"""
    return BlockNode(
        type="block",
        instructions=instructions or [],
        hash=hash_str,
        offset=offset,
        length=length,
        cell=cell
    )


def create_method(
    method_id: int,
    body: BlockNode,
    hash_str: str,
    offset: int
) -> MethodNode:
    """Create a MethodNode"""
    return MethodNode(
        type="method",
        id=method_id,
        body=body,
        hash=hash_str,
        offset=offset
    )


def create_procedure(
    hash_str: str,
    body: BlockNode
) -> ProcedureNode:
    """Create a ProcedureNode"""
    return ProcedureNode(
        type="procedure",
        hash=hash_str,
        body=body
    )


def create_program(
    top_level_instructions: List[InstructionNode],
    methods: List[MethodNode],
    procedures: List[ProcedureNode],
    with_refs: bool = False
) -> ProgramNode:
    """Create a ProgramNode"""
    return ProgramNode(
        type="program",
        top_level_instructions=top_level_instructions or [],
        methods=methods or [],
        procedures=procedures or [],
        with_refs=with_refs
    )
