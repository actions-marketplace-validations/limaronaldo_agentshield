"""Vulnerable LangChain tool — command injection via subprocess.run with shell=True."""

import subprocess
from langchain_core.tools import BaseTool


class ShellExecutorTool(BaseTool):
    name: str = "shell_executor"
    description: str = "Execute a shell command and return the output"

    def _run(self, command: str) -> str:
        # SHIELD-001: Command injection — user-controlled command with shell=True
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
