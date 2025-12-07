# ruff: noqa: D103
from __future__ import annotations

import filecmp
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from time import sleep

import pytest

USER_ID = "72057594037927937"
SYNC_1_SAV = Path(__file__).parent / "03 sync 11 - 72057594037927937.sav"
SYNC_1_YAML = Path(__file__).parent / "03 sync 11 - 72057594037927937.yaml"
SYNC_2_SAV = Path(__file__).parent / "04 sync 22 - 72057594037927937.sav"
SYNC_2_YAML = Path(__file__).parent / "04 sync 22 - 72057594037927937.yaml"


type Runner = Callable[[Path], None]


@pytest.fixture(scope="module")
def runner(pytestconfig: pytest.Config) -> Runner:
    def runner_func(folder: Path) -> None:
        args = [
            pytestconfig.getoption("--exe"),
            "s",
            USER_ID,
            folder,
        ]
        print(args)  # noqa: T201
        _ = subprocess.run(args, check=True)

    return runner_func


type CacheRunner = Callable[[Path], Callable[[], None]]


@pytest.fixture(scope="module")
def cache_runner(pytestconfig: pytest.Config) -> CacheRunner:
    def runner_func(folder: Path) -> Callable[[], None]:
        args = [
            pytestconfig.getoption("--exe"),
            "S",
            USER_ID,
            folder,
        ]

        print(args)  # noqa: T201
        proc = subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf8",
        )
        assert proc.stdout
        proc.stdout.readline()

        def finish() -> None:
            stdout, stderr = proc.communicate("g", timeout=1)
            assert not stdout and not stderr
            assert proc.wait(timeout=1) == 0

        return finish

    return runner_func


def test_no_yaml(runner: Runner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)

        runner(folder)

        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)


def test_no_sav(runner: Runner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_YAML, folder / SYNC_1_YAML.name)

        runner(folder)

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)


def test_sav_last_modified(runner: Runner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_YAML, folder / SYNC_1_YAML.name)
        shutil.copy(SYNC_2_SAV, folder / SYNC_1_SAV.name)

        runner(folder)

        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_1_YAML.name)


def test_yaml_last_modified(runner: Runner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        sleep(1)  # make sure the last modify time changed, equal timestamps favour .sav
        shutil.copy(SYNC_2_YAML, folder / SYNC_1_YAML.name)

        runner(folder)

        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_1_YAML.name)


def test_both_out_of_sync(runner: Runner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        # File 1 is sav last
        shutil.copy(SYNC_1_YAML, folder / SYNC_1_YAML.name)
        shutil.copy(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        # File 2 is yaml last
        shutil.copy(SYNC_1_SAV, folder / SYNC_2_SAV.name)
        sleep(1)
        shutil.copy(SYNC_2_YAML, folder / SYNC_2_YAML.name)

        runner(folder)

        # All of them have the file 2 contents
        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_1_YAML.name)
        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_2_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_2_YAML.name)


def test_cache_no_modifications(cache_runner: CacheRunner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)

        finish = cache_runner(folder)

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)

        finish()

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)


def test_cache_sav_modified(cache_runner: CacheRunner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)

        finish = cache_runner(folder)

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)

        shutil.copy(SYNC_2_SAV, folder / SYNC_1_SAV.name)

        finish()

        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_1_YAML.name)


def test_cache_yaml_modified(cache_runner: CacheRunner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)

        finish = cache_runner(folder)

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)

        shutil.copy(SYNC_2_YAML, folder / SYNC_1_YAML.name)

        finish()

        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_1_YAML.name)


def test_cache_new_file(cache_runner: CacheRunner) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        folder = Path(temp_dir)
        shutil.copy(SYNC_1_SAV, folder / SYNC_1_SAV.name)

        finish = cache_runner(folder)

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)

        shutil.copy(SYNC_2_YAML, folder / SYNC_2_YAML.name)

        finish()

        assert filecmp.cmp(SYNC_1_SAV, folder / SYNC_1_SAV.name)
        assert filecmp.cmp(SYNC_1_YAML, folder / SYNC_1_YAML.name)
        assert filecmp.cmp(SYNC_2_SAV, folder / SYNC_2_SAV.name)
        assert filecmp.cmp(SYNC_2_YAML, folder / SYNC_2_YAML.name)
