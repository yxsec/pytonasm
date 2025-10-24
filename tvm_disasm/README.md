# pytonasm (Python TON Assembler)

A Python implementation of the TON Virtual Machine (TVM) bytecode disassembler and analyzer. This tool converts TVM bytecode (BOC files) into human-readable Fift assembly code with comprehensive instruction analysis.

This is a Python port like [ton-opcode](https://github.com/tact-lang/ton-opcode) TypeScript library with additional features.

## Features

- Disassemble BoC files into Fift assembly
- Support for full TVM instruction set (CP0)
- Dictionary unpacking for methods and procedures
- Configurable output options (aliases, bitcode display, etc.)
- Command-line interface and Python API

## Installation

```bash
pip install pytoniq-core
```

## Usage

### Command Line

After installation via pip:

```bash
# Basic usage (Fift assembly)
pytonasm contract.boc

# Show detailed instructions
pytonasm contract.boc --mode instructions

# Show both formats
pytonasm contract.boc --mode both

# Show statistics
pytonasm contract.boc --stats

# With additional options
pytonasm contract.boc --mode instructions --show-offsets --show-bytecode
```

Or use Python module directly:

```bash
python -m tvm_disasm.main contract.boc
```

### Python API

```python
from pytoniq_core import Cell
from tvm_disasm import disassemble_root, AssemblyWriter

# Load BoC file
with open('contract.boc', 'rb') as f:
    boc_data = f.read()

source = Cell.one_from_boc(boc_data)

# Disassemble
program = disassemble_root(source, compute_refs=True)

# Write to assembly
assembly = AssemblyWriter.write(program, {
    'useAliases': True,
    'withoutHeader': False,
    'outputBitcodeAfterInstruction': False,
})

print(assembly)
```

### Raw Disassemble (Without Dictionary Unpacking)

```python
from tvm_disasm import disassemble_raw_root, AssemblyWriter

# Disassemble without dictionary unpacking
block = disassemble_raw_root(source)

assembly = AssemblyWriter.write(block, {})
print(assembly)
```

## API Reference

### Disassembler Functions

- `disassemble_root(cell, compute_refs=True)` - Disassemble root cell with dictionary unpacking
- `disassemble_raw_root(cell)` - Disassemble without dictionary unpacking
- `disassemble(source, offset_bits=0, offset_refs=0, limit_bits=None, limit_refs=None)` - Low-level disassemble function

### AssemblyWriter Options

- `useAliases` (bool) - Use opcode aliases for better readability (default: True)
- `withoutHeader` (bool) - Omit header comments (default: True)
- `outputBitcodeAfterInstruction` (bool) - Show hex bitcode as comments (default: False)

## Project Structure

```
tvm_disasm/
├── __init__.py              # Main package exports
├── main.py                  # CLI entry point
├── ast/                     # AST node definitions
│   ├── __init__.py
│   └── ast.py
├── decompiler/              # Decompiler logic
│   ├── __init__.py
│   ├── disasm.py           # Main disassembler
│   └── operand_loader.py   # Operand parsing
├── printer/                 # Assembly output
│   ├── __init__.py
│   ├── base_writer.py      # Text writer utility
│   └── assembly_writer.py  # Fift assembly generator
├── utils/                   # Utilities
│   ├── __init__.py
│   ├── binutils.py         # Binary utilities
│   └── prefix_matcher.py   # Opcode matching
└── spec/
    └── cp0.json            # TVM instruction set spec
```

## How It Works

1. **Bytecode Parsing**: The disassembler reads TVM bytecode from a Cell using pytoniq-core
2. **Prefix Matching**: Each instruction is identified by matching bit prefixes against the CP0 specification
3. **Operand Loading**: Instruction operands are decoded based on their type (uint, int, ref, subslice, etc.)
4. **AST Building**: Instructions are organized into an Abstract Syntax Tree (AST) with blocks, methods, and procedures
5. **Assembly Generation**: The AST is converted to human-readable Fift assembly code

## Differences from TypeScript Version

This Python implementation aims to maintain feature parity with the original TypeScript version while adapting to Python idioms:

- Uses `pytoniq-core` instead of `@ton/core`
- Uses Python dataclasses instead of TypeScript interfaces
- Follows Python naming conventions (snake_case vs camelCase)

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0).

For commercial licensing inquiries, please contact the project maintainers.

See the [LICENSE](../LICENSE) file for full details.

## Credits

Based on [ton-opcode](https://github.com/tact-lang/ton-opcode) 