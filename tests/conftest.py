"""Shared pytest fixtures: resolve the fixtures directory."""

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture()
def foundry_fixture() -> Path:
    return FIXTURES / "foundry_safe"


@pytest.fixture()
def hardhat_fixture() -> Path:
    return FIXTURES / "hardhat_safe"
