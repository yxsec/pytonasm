#!/usr/bin/env python3
"""
Main entry point for pytonasm command-line interface.
"""
import sys
import argparse
from pytoniq_core import Cell
from .decompiler import disassemble_raw_root
from .printer import AssemblyWriter, InstructionWriter
from .ast.ast import ProgramNode, BlockNode


def load_boc_file(file_path: str) -> Cell:
    """
    Load a BoC file and return the root cell.

    Args:
        file_path: Path to the BoC file

    Returns:
        The root Cell
    """
    with open(file_path, 'rb') as f:
        boc_data = f.read()

    # Parse BoC
    cells = Cell.one_from_boc(boc_data)
    return cells


def show_statistics(program):
    """Display instruction statistics"""
    # Get instructions based on node type
    if isinstance(program, ProgramNode):
        instructions = program.top_level_instructions
        print(f"\n{'=' * 80}")
        print("PROGRAM STATISTICS")
        print("=" * 80)
        print(f"Methods: {len(program.methods)}")
        print(f"Procedures: {len(program.procedures)}")
        print(f"Top-level instructions: {len(instructions)}")
    elif isinstance(program, BlockNode):
        instructions = program.instructions
        print(f"\n{'=' * 80}")
        print("PROGRAM STATISTICS")
        print("=" * 80)
        print(f"Instructions: {len(instructions)}")
    else:
        return

    if not instructions:
        return

    # Count opcode frequencies
    opcode_counts = {}
    for inst in instructions:
        opcode = inst.opcode.definition['mnemonic']
        opcode_counts[opcode] = opcode_counts.get(opcode, 0) + 1

    # Display top opcodes
    print(f"\nTop 10 Opcodes:")
    for opcode, count in sorted(opcode_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {opcode:<25s}: {count:3d} occurrences")


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        prog='pytonasm',
        description='pytonasm - Python TVM bytecode disassembler and analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  pytonasm contract.boc                           # Fift assembly
  pytonasm contract.boc --mode instructions       # Instruction details
  pytonasm contract.boc --mode both               # Both formats
  pytonasm contract.boc --stats                   # Show statistics

Note: If your filename starts with '-', use one of these:
  pytonasm -- -1_hash.boc                         # Use -- separator
  pytonasm ./-1_hash.boc                          # Use relative path
        """
    )

    parser.add_argument('boc_file', nargs='?', help='Path to BOC file')
    parser.add_argument('--mode', choices=['fift', 'instructions', 'both'],
                       default='fift', help='Output mode (default: fift)')
    parser.add_argument('--show-offsets', action='store_true',
                       help='Show instruction bit offsets')
    parser.add_argument('--show-bytecode', action='store_true',
                       help='Show bytecode hex values')
    parser.add_argument('--stats', action='store_true',
                       help='Show instruction statistics')

    args = parser.parse_args()

    # Check if boc_file is provided
    if not args.boc_file:
        parser.print_help()
        print("\nError: BOC file is required", file=sys.stderr)
        sys.exit(1)

    # Read BOC file
    try:
        with open(args.boc_file, 'rb') as f:
            boc_data = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {args.boc_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    # Parse BOC to Cell
    try:
        cell = Cell.one_from_boc(boc_data)
    except Exception as e:
        print(f"Error parsing BOC: {e}", file=sys.stderr)
        sys.exit(1)

    # Disassemble to AST
    try:
        program = disassemble_raw_root(cell)
    except Exception as e:
        print(f"Error disassembling: {e}", file=sys.stderr)
        sys.exit(1)

    # Output based on mode
    if args.mode in ['fift', 'both']:
        if args.mode == 'both':
            print("=" * 80)
            print("FIFT ASSEMBLY")
            print("=" * 80)

        fift_code = AssemblyWriter.write(program)
        print(fift_code)

        if args.mode == 'both':
            print("\n")

    if args.mode in ['instructions', 'both']:
        if args.mode == 'both':
            print("=" * 80)
            print("INSTRUCTION DETAILS")
            print("=" * 80)

        instruction_output = InstructionWriter.write(program, options={
            'showOffsets': args.show_offsets or args.mode == 'both',
            'showBytecode': args.show_bytecode or args.mode == 'both',
            'showOperandDetails': False
        })
        print(instruction_output)

    # Show statistics if requested
    if args.stats:
        show_statistics(program)


if __name__ == '__main__':
    main()
