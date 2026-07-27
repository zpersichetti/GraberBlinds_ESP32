"""Enable `python -m harness ...`, the invocation used throughout HANDOFF.md, README.md,
CLAUDE.md and .claude/commands/map-live.md. The pyproject console script (`harness`) and
this entry point both dispatch to the same Typer app.
"""
from .cli import app

app()
