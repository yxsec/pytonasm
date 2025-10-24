# pytonasm

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

**Python TON Assembler** - A Python implementation of TVM (TON Virtual Machine) bytecode disassembler with full instruction analysis and Fift assembly code generation.

## Features

- ✅ **Complete TVM bytecode disassembly** from BOC (Bag of Cells) files
- ✅ **AST generation** with full instruction details (opcode, operands, offsets)
- ✅ **Fift assembly output** compatible with TON toolchain
- ✅ **Instruction-level analysis** with opcodes, bytecodes, and operands
- ✅ **Cell reference handling** with recursive expansion
- ✅ **Comprehensive operand parsing** (numeric, bigint, ref, subslice)
- ✅ **Based on official TVM specification** (cp0.json opcode definitions)
- ✅ **Dual output modes** - Fift assembly and detailed instruction analysis

## Installation

### From PyPI (Recommended)

```bash
pip install pytonasm
```

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/pytonasm.git
cd pytonasm

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Dependencies

- `pytoniq-core` - TON blockchain core library for BOC parsing

## Quick Start

### Python API

#### Basic Usage: Fift Assembly Output

```python
from pytoniq_core import Cell
from tvm_disasm import disassemble_raw_root, AssemblyWriter

# Load BOC file
with open('contract.boc', 'rb') as f:
    boc_data = f.read()

# Parse BOC to Cell
cell = Cell.one_from_boc(boc_data)

# Disassemble to AST
program_ast = disassemble_raw_root(cell)

# Generate Fift assembly
fift_code = AssemblyWriter.write(program_ast)
print(fift_code)
```

#### Instruction-Level Analysis

```python
from pytoniq_core import Cell
from tvm_disasm import disassemble_raw_root, InstructionWriter

# Load and parse BOC
with open('contract.boc', 'rb') as f:
    cell = Cell.one_from_boc(f.read())

# Disassemble to AST
program_ast = disassemble_raw_root(cell)

# Generate detailed instruction output
instruction_output = InstructionWriter.write(program_ast, options={
    'showOffsets': True,       # Show instruction bit offsets
    'showBytecode': True,      # Show hex bytecode values
    'showOperandDetails': False # Show detailed operand info
})
print(instruction_output)
```

**Example output:**
```
================================================================================
TVM PROGRAM DISASSEMBLY
================================================================================

Block (hash: 587cc789eff1c84f..., 46 instructions):
--------------------------------------------------------------------------------
[   1] @   0 (16b) SETCP                | args: 0 | bytecode: 0xFF
[   2] @  16 ( 8b) PUSH                 | args: s0 | bytecode: 0x2
[   3] @  24 ( 8b) IFNOTRET             | bytecode: 0xDD
[   4] @  32 ( 8b) PUSH                 | args: s0 | bytecode: 0x2
[   5] @  40 (32b) PUSHINT_LONG         | args: 85143 | bytecode: 0x82
[   6] @  72 ( 8b) EQUAL                | bytecode: 0xBA
...
```

### Command Line Usage

After installation, use the `pytonasm` command:

```bash
# Output Fift assembly (default)
pytonasm contract.boc

# Output detailed instruction information
pytonasm contract.boc --mode instructions

# Output both Fift and instructions
pytonasm contract.boc --mode both

# Show instruction statistics
pytonasm contract.boc --stats

# With additional options
pytonasm contract.boc --mode instructions --show-offsets --show-bytecode

# For files starting with '-', use '--' separator
pytonasm -- -1_hash.boc
```

Or use the included `example.py` script directly:

```bash
python example.py contract.boc
```

## Project Structure

```
tvm_disasm/
├── __init__.py              # Package initialization
├── decompiler/              # Core disassembly logic
│   ├── disasm.py            # Main disassembler
│   └── operand_loader.py    # Operand parsing logic
├── printer/                 # Output generation
│   ├── assembly_writer.py   # Fift code generator
│   ├── instruction_writer.py # Instruction details generator
│   └── base_writer.py       # Base writer class
├── ast/                     # AST node definitions
│   └── ast.py               # BlockNode, InstructionNode, etc.
├── utils/                   # Utility functions
│   ├── prefix_matcher.py    # Opcode prefix matching
│   └── binutils.py          # Binary utilities
└── spec/
    └── cp0.json             # TVM Codepage 0 instruction definitions

example.py                   # Complete usage example with all features
requirements.txt             # Python dependencies
setup.py                     # Package installation config
LICENSE                      # CC BY-NC-SA 4.0 License
```

## Architecture

### Disassembly Pipeline

```
BOC File → Cell → Slice → PrefixMatcher → DecodedInstruction → AST → Fift
```

### Key Components

1. **Prefix Matcher**: Matches bytecode prefixes to instruction definitions from `cp0.json`
2. **Operand Loader**: Parses instruction operands (numeric, ref, subslice, bigint)
3. **Disassembler**: Orchestrates the disassembly process
4. **Assembly Writer**: Generates human-readable Fift assembly code
5. **Instruction Writer**: Generates detailed opcode instruction information

### Cell Reference Handling

The implementation correctly handles Cell references with recursive expansion:

```python
def _write_cell_slice(self, cell: Cell) -> None:
    """Write a Cell as Fift slice notation, recursively expanding refs."""
    hex_str = self._bits_to_hex(cell.bits)
    self.writer.write_line(hex_str)

    # Recursively write refs
    for ref in cell.refs:
        self._write_cell_slice(ref)
```

## Output Formats

The TVM Disassembler provides two complementary output formats:

### 1. Fift Assembly (via AssemblyWriter)

Generates Fift assembly code compatible with TON's toolchain:

```fift
"Asm.fif" include
<{
  SETCP0
  s0 PUSH
  IFNOTRET
  85143 PUSHINT
  EQUAL
  s1 PUSH
  78748 PUSHINT
  EQUAL
  OR
}>c
```

**Use cases:**
- Compiling back to TVM bytecode
- Integration with TON development tools
- Smart contract analysis and modification

### 2. Instruction Details (via InstructionWriter)

Provides detailed opcode-level information for analysis:

```
[   1] @   0 (16b) SETCP                | args: 0 | bytecode: 0xFF
[   2] @  16 ( 8b) PUSH                 | args: s0 | bytecode: 0x2
[   3] @  24 ( 8b) IFNOTRET             | bytecode: 0xDD
[   4] @  32 ( 8b) PUSH                 | args: s0 | bytecode: 0x2
[   5] @  40 (32b) PUSHINT_LONG         | args: 85143 | bytecode: 0x82
```

**Fields:**
- `[N]`: Instruction number
- `@offset`: Bit offset in the bytecode
- `(Nb)`: Instruction length in bits
- `OPCODE`: Instruction mnemonic
- `args:`: Operand values
- `bytecode:`: Hex bytecode prefix

**Use cases:**
- Bytecode analysis and debugging
- Understanding instruction encoding
- Security auditing
- Educational purposes

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

**You are free to:**
- ✅ Use for personal projects
- ✅ Use for research and education
- ✅ Use for open-source projects
- ✅ Modify and distribute (under same license)

**You may NOT:**
- ❌ Use for commercial purposes without permission
- ❌ Sell or monetize this software

For commercial licensing, please contact the project maintainers.

See the [LICENSE](LICENSE) file for full details.

## Use Cases

- **Smart Contract Analysis**: Understand and audit TON smart contracts
- **Security Research**: Analyze contract bytecode for vulnerabilities
- **Development Tools**: Build developer tools for TON ecosystem
- **Education**: Learn TVM instruction set and execution model
- **Debugging**: Debug compiled smart contracts

## Contributing

Contributions are welcome! Areas for contribution:
- Additional output formats (JSON, GraphViz, etc.)
- Performance optimizations
- Enhanced error messages
- Documentation improvements
- Unit tests

## Acknowledgments

This project builds upon the excellent work of the TON community:

- **[ton-opcode](https://github.com/tact-lang/ton-opcode)** by Tact Lang - Original TypeScript implementation that inspired this Python port
- **[tvm-spec](https://github.com/ton-community/tvm-spec)** by TON Community - Comprehensive TVM instruction set specification (cp0.json)
- **[TON Blockchain](https://ton.org)** - Official TVM specification and documentation
- **[pytoniq-core](https://github.com/yungwine/pytoniq-core)** - Python library for BOC parsing and TON core functionality

Special thanks to the TON developer community for their continuous contributions to the ecosystem.

## References

- [TVM Whitepaper](https://ton.org/tvm.pdf) - Official TVM specification
- [TVM Specification](https://github.com/ton-community/tvm-spec) - Community-maintained TVM instruction set
- [Fift Documentation](https://ton.org/fiftbase.pdf) - Fift assembly language guide
- [TON Documentation](https://docs.ton.org/) - Comprehensive TON blockchain docs
- [ton-opcode Repository](https://github.com/tact-lang/ton-opcode) - Original TypeScript implementation
