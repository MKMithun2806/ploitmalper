"""CLI subcommands and argument parsing."""

from ploit_malper.cli.main import main
from ploit_malper.cli.recipe import build_recipe, get_available_platforms, get_available_arches

__all__ = ["main", "build_recipe", "get_available_platforms", "get_available_arches"]
