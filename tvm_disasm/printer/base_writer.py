"""
Base writer for generating formatted text output.
"""
from typing import List, Callable


class BaseWriter:
    """
    A text writer that handles indentation and line management.
    """

    def __init__(self):
        self.lines: List[str] = []
        self.indent_level: int = 0
        self.current_line: str = ""

    def indent(self, handler: Callable[[], None]) -> None:
        """
        Execute handler with increased indentation level.

        Args:
            handler: Function to execute with indentation
        """
        self.indent_level += 1
        try:
            handler()
        finally:
            self.indent_level -= 1

    def write(self, src: str) -> None:
        """
        Append text to the current line.

        Args:
            src: Text to append
        """
        self.current_line += src

    def new_line(self) -> None:
        """Finish the current line and start a new one."""
        self.lines.append(" " * (self.indent_level * 2) + self.current_line)
        self.current_line = ""

    def write_line(self, src: str) -> None:
        """
        Append text to the current line and finish it.

        Args:
            src: Text to append
        """
        self.lines.append(" " * (self.indent_level * 2) + self.current_line + src)
        self.current_line = ""

    def end(self) -> str:
        """
        Finish writing and return the complete text.

        Returns:
            All lines joined with newlines
        """
        if self.current_line:
            self.new_line()
        return "\n".join(self.lines)

    def line_length(self) -> int:
        """
        Get the current line length including indentation.

        Returns:
            Length of current line with indentation
        """
        return len(self.current_line) + self.indent_level * 2
