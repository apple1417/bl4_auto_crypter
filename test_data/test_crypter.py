# ruff: noqa: D103
from __future__ import annotations

import filecmp
import platform
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

TEST_DATA_FOLDER = Path(__file__).parent
TEST_DATA = [
    (sav, yaml, match.group(1))
    for sav in TEST_DATA_FOLDER.glob("*.sav")
    if (yaml := sav.with_suffix(".yaml")).exists()
    if (match := re.match(r".+ \- (.+)\.sav", sav.name)) is not None
]

parameterize_test_data = pytest.mark.parametrize(
    "sav, yaml, user_id",
    TEST_DATA,
    ids=[x[0].name for x in TEST_DATA],
)


type Runner = Callable[[Literal["e", "d"], str, Path | str, Path | str], None]


@pytest.fixture(scope="module")
def runner(pytestconfig: pytest.Config) -> Runner:
    def runner_func(
        encrypt: Literal["e", "d"],
        user_id: str,
        input_file: Path | str,
        output_file: Path | str,
    ) -> None:
        args = [
            pytestconfig.getoption("--exe"),
            encrypt,
            user_id,
            input_file,
            output_file,
        ]
        if platform.system() != "Windows":
            args.insert(0, "wine")
        print(args)  # noqa: T201
        _ = subprocess.run(args, check=True)

    return runner_func


@parameterize_test_data
def test_decryption(runner: Runner, sav: Path, yaml: Path, user_id: str) -> None:
    with tempfile.NamedTemporaryFile() as temp:
        temp.close()

        runner("d", user_id, sav, temp.name)
        assert filecmp.cmp(yaml, temp.name)


@parameterize_test_data
def test_encryption(runner: Runner, sav: Path, yaml: Path, user_id: str) -> None:
    with tempfile.NamedTemporaryFile() as temp:
        temp.close()

        runner("e", user_id, yaml, temp.name)
        assert filecmp.cmp(sav, temp.name)


@parameterize_test_data
def test_sav_roundtrip(runner: Runner, sav: Path, yaml: Path, user_id: str) -> None:
    del yaml

    with (
        tempfile.NamedTemporaryFile() as temp_yaml,
        tempfile.NamedTemporaryFile() as temp_sav,
    ):
        temp_yaml.close()
        temp_sav.close()

        runner("d", user_id, sav, temp_yaml.name)
        runner("e", user_id, temp_yaml.name, temp_sav.name)
        assert filecmp.cmp(sav, temp_sav.name)


@parameterize_test_data
def test_yaml_roundtrip(runner: Runner, sav: Path, yaml: Path, user_id: str) -> None:
    del sav

    with (
        tempfile.NamedTemporaryFile() as temp_yaml,
        tempfile.NamedTemporaryFile() as temp_sav,
    ):
        temp_yaml.close()
        temp_sav.close()

        runner("e", user_id, yaml, temp_sav.name)
        runner("d", user_id, temp_sav.name, temp_yaml.name)
        assert filecmp.cmp(yaml, temp_yaml.name)
