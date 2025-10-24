#!/usr/bin/env python3
"""
Main entry point for TVM disassembler command-line interface.
"""
import sys
import argparse
from pathlib import Path
from pytoniq_core import Cell
from .decompiler import disassemble_root, disassemble_raw_root
from .printer import AssemblyWriter


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


def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description='TVM Bytecode Disassembler - Convert BoC files to Fift assembly'
    )

    parser.add_argument(
        'input',
        help='Input BoC file path'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output file path (default: stdout)',
        default=None
    )

    parser.add_argument(
        '--raw',
        action='store_true',
        help='Disassemble without unpacking dictionary (raw mode)'
    )

    parser.add_argument(
        '--no-refs',
        action='store_true',
        help='Do not extract references into separate functions'
    )

    parser.add_argument(
        '--show-bitcode',
        action='store_true',
        help='Show binary representation as comments after each instruction'
    )

    parser.add_argument(
        '--no-aliases',
        action='store_true',
        help='Disable opcode aliases for better readability'
    )

    parser.add_argument(
        '--with-header',
        action='store_true',
        help='Include header comments in output'
    )

    args = parser.parse_args()

    try:
        # Load input file
        cell = load_boc_file(args.input)

        # Disassemble
        if args.raw:
            program = disassemble_raw_root(cell)
        else:
            program = disassemble_root(cell, compute_refs=not args.no_refs)

        # Write assembly
        options = {
            'useAliases': not args.no_aliases,
            'withoutHeader': not args.with_header,
            'outputBitcodeAfterInstruction': args.show_bitcode,
        }

        assembly = AssemblyWriter.write(program, options)

        # Output
        if args.output:
            Path(args.output).write_text(assembly)
            print(f"Disassembly written to {args.output}", file=sys.stderr)
        else:
            print(assembly)

    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
