#!/usr/bin/env python3
"""
TVM Disassembler - Example Usage

Demonstrates the core functionality of the TVM Disassembler.

Usage:
    python example.py <contract.boc> [OPTIONS]

Options:
    --mode MODE        Output mode: fift, instructions, or both (default: fift)
    --show-offsets     Show instruction bit offsets and lengths
    --show-bytecode    Show bytecode hex values
    --stats            Show instruction statistics
    -h, --help         Show this help message

Examples:
    python example.py contract.boc
    python example.py contract.boc --mode instructions
    python example.py contract.boc --mode both
    python example.py contract.boc --stats
"""
import sys
import argparse
from pytoniq_core import Cell
from tvm_disasm import disassemble_raw_root, AssemblyWriter, InstructionWriter


def show_statistics(program):
    """Display instruction statistics"""
    from tvm_disasm import ProgramNode, BlockNode

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
    parser = argparse.ArgumentParser(
        description='TVM Disassembler - Disassemble TVM bytecode from BOC files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python example.py contract.boc                      # Fift assembly
  python example.py contract.boc --mode instructions  # Instruction details
  python example.py contract.boc --mode both          # Both formats
  python example.py contract.boc --stats              # Show statistics

Note: If your filename starts with '-', use one of these:
  python example.py -- -1_hash.boc                    # Use -- separator
  python example.py ./-1_hash.boc                     # Use relative path
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
