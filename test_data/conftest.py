# ruff: noqa: D103
import pytest


def pytest_addoption(parser: pytest.OptionGroup) -> None:
    parser.addoption("--exe", required=True, help="crypter exe to run")
