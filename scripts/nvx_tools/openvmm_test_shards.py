"""The shards of the OpenVMM VMM tests, which CI runs in parallel.

doc/ci.md#openvmm-vmm-test-shards describes the partition, how this module
plans it from test duration reports, and when to plan it again.
"""

from __future__ import annotations

import argparse
import heapq
import json
import statistics
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from . import shard_plans
from .ci import (
    OPENVMM_TEST_BACKENDS,
    OPENVMM_TEST_DURATIONS_NAME,
    OPENVMM_TEST_DURATIONS_SCHEMA,
    OPENVMM_TEST_DURATIONS_SCHEMA_VERSION,
    OPENVMM_TEST_SELECTIONS,
    OpenVMMTestShard,
)
from .common import ScriptError, strict_json_object

PARTITION_PATH = Path(__file__).with_name("openvmm_test_shards.json")
SCHEMA = "nvx-openvmm-test-shards"
SCHEMA_VERSION = 1
PLAN_ADVICE = (
    "plan the shards again with `nvx.py plan-openvmm-test-shards` "
    "(doc/ci.md#openvmm-vmm-test-shards)"
)
# OpenVMM's .config/nextest.toml has a VMM test require 32 of nextest's test
# threads when its name holds very_heavy, 12 when it holds heavy, and 2
# otherwise. nextest gives a test that requires more threads than it runs all
# of them, so that the test runs alone.
THREADS_REQUIRED = (("very_heavy", 32), ("heavy", 12))
DEFAULT_THREADS_REQUIRED = 2


def threads_required(test: str, test_threads: int) -> int:
    """Return how many of nextest's test threads a VMM test takes."""
    required = next(
        (threads for marker, threads in THREADS_REQUIRED if marker in test),
        DEFAULT_THREADS_REQUIRED,
    )
    return min(required, test_threads)


def run_tenths(
    tests: Iterable[str], tenths: Mapping[str, int], test_threads: int
) -> int:
    """Return how long nextest takes to run the tests, in tenths of a second,
    from the duration of each.

    nextest starts the tests in name order, each as soon as it has the test
    threads that the test requires, and never one before an earlier one: a
    test that takes every thread waits for each earlier test to end, and each
    later test waits for it.
    """
    running: list[tuple[int, int]] = []
    free = test_threads
    now = 0
    for test in sorted(tests):
        required = threads_required(test, test_threads)
        while free < required:
            ended, threads = heapq.heappop(running)
            now = max(now, ended)
            free += threads
        heapq.heappush(running, (now + tenths[test], required))
        free -= required
    return max((ended for ended, _ in running), default=0)


@dataclass(frozen=True)
class BackendShards:
    """One backend's partition of its tests: the test threads with which
    nextest runs them, one for each logical processor of the backend's
    runners, each test's median duration in seconds, and the tests of each
    shard, in shard order."""

    test_threads: int
    seconds: Mapping[str, float]
    shards: tuple[tuple[str, ...], ...]

    def run_seconds(self, tests: Iterable[str]) -> float:
        """Return how long nextest takes to run some of the tests."""
        durations = {
            test: shard_plans.tenths(duration)
            for test, duration in self.seconds.items()
        }
        return run_tenths(tests, durations, self.test_threads) / 10

    def shard_seconds(self) -> tuple[float, ...]:
        """Return how long nextest takes to run each shard's tests."""
        return tuple(self.run_seconds(shard) for shard in self.shards)


@dataclass(frozen=True)
class Partition:
    """The shards of each sharded backend, and the CI runs, as
    `<run-id>-<attempt>`, whose reports gave the durations."""

    runs: tuple[str, ...]
    backends: Mapping[str, BackendShards]


def _backend_shards(value: object) -> BackendShards | None:
    document = shard_plans.json_object(value, ("test_threads", "seconds", "shards"))
    if document is None:
        return None
    test_threads = document["test_threads"]
    raw_seconds = document["seconds"]
    raw_shards = document["shards"]
    if (
        isinstance(test_threads, bool)
        or not isinstance(test_threads, int)
        or test_threads < 1
        or not isinstance(raw_seconds, dict)
        or not isinstance(raw_shards, list)
    ):
        return None
    seconds: dict[str, float] = {}
    for test, duration in cast(dict[str, object], raw_seconds).items():
        number = shard_plans.json_number(duration)
        if number is None or number < 0:
            return None
        seconds[test] = number
    shards: list[tuple[str, ...]] = []
    for raw_shard in cast(list[object], raw_shards):
        shard = shard_plans.json_object(raw_shard, ("seconds", "tests"))
        if shard is None or shard_plans.json_number(shard["seconds"]) is None:
            return None
        tests = shard_plans.json_strings(shard["tests"])
        if tests is None:
            return None
        shards.append(tests)
    return BackendShards(test_threads, seconds, tuple(shards))


def load_partition(path: Path = PARTITION_PATH) -> Partition:
    """Read a partition, failing unless its structure is valid; whether it
    partitions each sharded backend's tests is check_partition()'s question."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ScriptError(f"{path} does not exist; {PLAN_ADVICE}") from None
    try:
        value: object = json.loads(text, object_pairs_hook=strict_json_object)
    except ValueError as error:
        raise ScriptError(f"{path} is not valid JSON: {error}") from error
    document = shard_plans.json_object(
        value, ("schema", "schema_version", "runs", "backends")
    )
    if (
        document is None
        or document["schema"] != SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise ScriptError(
            f"{path} is not an {SCHEMA} document of schema version {SCHEMA_VERSION}"
        )
    runs = shard_plans.json_strings(document["runs"])
    raw_backends = document["backends"]
    if runs is None or not isinstance(raw_backends, dict):
        raise ScriptError(f"{path} has malformed runs or backends")
    backends: dict[str, BackendShards] = {}
    for backend, raw in cast(dict[str, object], raw_backends).items():
        shards = _backend_shards(raw)
        if shards is None:
            raise ScriptError(f"{path} has a malformed partition of {backend}")
        backends[backend] = shards
    return Partition(runs, backends)


def partition_problems(partition: Partition) -> list[str]:
    """Return how a partition fails to put each test that a sharded backend's
    filter selects in exactly one of the backend's shards, with its
    duration."""
    problems: list[str] = []
    for backend, shards in partition.backends.items():
        selection = OPENVMM_TEST_SELECTIONS.get(backend)
        if selection is None:
            problems.append(f"{backend} has no filter that names each of its tests")
            continue
        if not shards.shards:
            problems.append(f"{backend} has no shards")
        expected = set(selection)
        placements: dict[str, list[int]] = {}
        for index, shard in enumerate(shards.shards, 1):
            if not shard:
                problems.append(f"{backend} shard {index} is empty")
            for test in shard:
                placements.setdefault(test, []).append(index)
        for test in selection:
            found = placements.get(test, [])
            if not found:
                problems.append(f"{backend}: {test} is in no shard")
            elif len(found) > 1:
                problems.append(
                    f"{backend}: {test} is in more than one shard: "
                    + ", ".join(str(index) for index in found)
                )
        for test in sorted(set(placements) - expected):
            problems.append(f"{backend}: {test} is not a test of its filter")
        for test in selection:
            if test not in shards.seconds:
                problems.append(f"{backend}: {test} has no duration")
        for test in sorted(set(shards.seconds) - expected):
            problems.append(
                f"{backend}: {test} has a duration but is not a test of its filter"
            )
    return problems


def check_partition(partition: Partition, path: Path = PARTITION_PATH) -> None:
    """Fail unless the partition puts each test that a sharded backend's
    filter selects in exactly one of the backend's shards."""
    problems = partition_problems(partition)
    if problems:
        raise ScriptError(
            f"{path} does not put each test of a sharded OpenVMM filter in "
            f"exactly one shard: {'; '.join(problems)}; {PLAN_ADVICE}"
        )


def select_shard(
    backend: str,
    shard: tuple[int, int],
    path: Path = PARTITION_PATH,
) -> OpenVMMTestShard:
    """Return shard INDEX of the COUNT shards of the backend's tests, with its
    tests in the order of the backend's filter, once the partition is checked
    and has COUNT shards for the backend."""
    partition = load_partition(path)
    check_partition(partition, path)
    index, count = shard
    shards = partition.backends.get(backend)
    if shards is None:
        raise ScriptError(
            f"{path} does not shard the {backend.upper()} tests, which CI runs "
            "in one job (doc/ci.md#openvmm-vmm-test-shards)"
        )
    if count != len(shards.shards):
        raise ScriptError(
            f"{path} splits the {backend.upper()} tests into "
            f"{len(shards.shards)} shards, but this run is shard {index} of "
            f"{count}; CI must run one job for each shard "
            "(doc/ci.md#openvmm-vmm-test-shards)"
        )
    selected = set(shards.shards[index - 1])
    return OpenVMMTestShard(
        index,
        count,
        tuple(test for test in OPENVMM_TEST_SELECTIONS[backend] if test in selected),
    )


def read_reports(
    paths: Iterable[Path],
) -> tuple[dict[str, dict[str, list[float]]], set[str], dict[str, set[int]]]:
    """Return each backend's samples of the duration of each of its tests,
    the CI runs that they come from, and the logical processors of the
    runners that took them.

    A sample is one report's time of a test that passed, in a run of the
    backend's tests or of a shard of them.
    """
    samples: dict[str, dict[str, list[float]]] = {}
    runs: set[str] = set()
    processors: dict[str, set[int]] = {}
    documents: set[str] = set()
    for path in shard_plans.report_paths(paths, OPENVMM_TEST_DURATIONS_NAME):
        try:
            value: object = json.loads(
                path.read_text(encoding="utf-8"), object_pairs_hook=strict_json_object
            )
        except ValueError as error:
            raise ScriptError(f"{path} is not valid JSON: {error}") from error
        document = cast(dict[str, object], value) if isinstance(value, dict) else {}
        if (
            document.get("schema") != OPENVMM_TEST_DURATIONS_SCHEMA
            or document.get("schema_version") != OPENVMM_TEST_DURATIONS_SCHEMA_VERSION
        ):
            raise ScriptError(
                f"{path} is not a test duration report of schema version "
                f"{OPENVMM_TEST_DURATIONS_SCHEMA_VERSION}"
            )
        backend = document.get("backend")
        tests = document.get("tests")
        if backend not in OPENVMM_TEST_BACKENDS or not isinstance(tests, list):
            raise ScriptError(f"{path} has a malformed backend or tests")
        backend = cast(str, backend)
        # The same report found twice counts once.
        identity = json.dumps(document, sort_keys=True)
        if identity in documents:
            continue
        documents.add(identity)
        measured = False
        for raw_test in cast(list[object], tests):
            test = (
                cast(dict[str, object], raw_test) if isinstance(raw_test, dict) else {}
            )
            name = test.get("test")
            seconds = shard_plans.json_number(test.get("seconds"))
            if not isinstance(name, str) or seconds is None or seconds < 0:
                raise ScriptError(f"{path} has a malformed test")
            if test.get("outcome") != "passed":
                continue
            samples.setdefault(backend, {}).setdefault(name, []).append(seconds)
            measured = True
        if not measured:
            continue
        github = document.get("github")
        if isinstance(github, dict):
            job = cast(dict[str, object], github)
            run_id, attempt = job.get("run_id"), job.get("run_attempt")
            if isinstance(run_id, str) and isinstance(attempt, str):
                runs.add(f"{run_id}-{attempt}")
        logical = document.get("logical_processors")
        if isinstance(logical, int) and not isinstance(logical, bool) and logical > 0:
            processors.setdefault(backend, set()).add(logical)
    return samples, runs, processors


def plan_partition(
    previous: Partition | None,
    *,
    samples: Mapping[str, Mapping[str, Sequence[float]]],
    runs: Collection[str],
    estimates: Mapping[str, float],
    counts: Mapping[str, int],
    test_threads: Mapping[str, int],
) -> Partition:
    """Plan the shards of each backend that `previous` shards, or that
    `counts` or `test_threads` names.

    A test's duration is its estimate, if given, or else the median of the
    backend's samples, to a tenth of a second, or else its duration in
    `previous`. A backend keeps its number of shards and its test threads
    unless `counts` or `test_threads` changes them, and its tests start in
    their shards of `previous`. A shard takes as long as nextest takes to run
    its tests with the backend's test threads (run_tenths), which the plan
    balances with shard_plans.plan_shards.
    """
    backends: dict[str, BackendShards] = {}
    missing: list[str] = []
    planned = [
        backend
        for backend in OPENVMM_TEST_BACKENDS
        if (previous is not None and backend in previous.backends)
        or backend in counts
        or backend in test_threads
    ]
    if not planned:
        raise ScriptError(
            "the partition shards no backend; pass --shards BACKEND=COUNT"
        )
    for backend in planned:
        selection = OPENVMM_TEST_SELECTIONS.get(backend)
        if selection is None:
            raise ScriptError(
                f"the {backend.upper()} filter selects its tests by pattern, so no "
                "partition can list them; only the tests of "
                + ", ".join(name.upper() for name in OPENVMM_TEST_SELECTIONS)
                + " have shards"
            )
        old = previous.backends.get(backend) if previous is not None else None
        measured = samples.get(backend, {})
        seconds: dict[str, float] = {}
        for test in selection:
            if test in estimates:
                seconds[test] = round(estimates[test], 1)
            elif measured.get(test):
                seconds[test] = round(statistics.median(measured[test]), 1)
            elif old is not None and test in old.seconds:
                seconds[test] = old.seconds[test]
            else:
                missing.append(f"{test} on {backend}")
        count = counts.get(backend, len(old.shards) if old is not None else 0)
        if count == 0:
            raise ScriptError(
                f"the partition has no {backend} shards; pass --shards {backend}=COUNT"
            )
        threads = test_threads.get(backend, old.test_threads if old is not None else 0)
        if threads == 0:
            raise ScriptError(
                f"the partition has no {backend} test threads; pass "
                f"--test-threads {backend}=COUNT"
            )
        if missing:
            continue
        durations = {
            test: shard_plans.tenths(duration) for test, duration in seconds.items()
        }
        backends[backend] = BackendShards(
            threads,
            seconds,
            shard_plans.plan_shards(
                seconds,
                count,
                old.shards if old is not None else (),
                cost=lambda tests, durations=durations, threads=threads: run_tenths(
                    tests, durations, threads
                ),
                noun="tests",
            ),
        )
    if missing:
        raise ScriptError(
            "no report measures, and the partition has no duration of, "
            + ", ".join(missing)
            + "; pass --report with a report that measures them, or --seconds "
            "TEST=SECONDS with an estimate"
        )
    planned_runs = (
        tuple(sorted(runs, key=shard_plans.run_order))
        if samples
        else (previous.runs if previous is not None else ())
    )
    return Partition(planned_runs, backends)


def partition_json(partition: Partition) -> str:
    """Return a partition as its file holds it."""
    document = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "runs": list(partition.runs),
        "backends": {
            backend: {
                "test_threads": shards.test_threads,
                "seconds": {
                    test: shards.seconds[test] for test in sorted(shards.seconds)
                },
                "shards": [
                    {"seconds": total, "tests": list(shard)}
                    for shard, total in zip(
                        shards.shards, shards.shard_seconds(), strict=True
                    )
                ],
            }
            for backend, shards in partition.backends.items()
        },
    }
    return json.dumps(document, indent=2) + "\n"


def describe_partition(previous: Partition | None, partition: Partition) -> str:
    """Return each backend's shards, with how long nextest takes to run them
    and all of the backend's tests, and the tests that changed shard."""
    lines: list[str] = []
    for backend, shards in partition.backends.items():
        lines.append(
            f"{backend}: {len(shards.shards)} shards of {len(shards.seconds)} "
            f"tests, which take {shards.run_seconds(shards.seconds):.1f} s "
            f"unsharded with {shards.test_threads} test threads"
        )
        for index, (shard, total) in enumerate(
            zip(shards.shards, shards.shard_seconds(), strict=True), 1
        ):
            lines.append(f"  shard {index}: {total:.1f} s, {len(shard)} tests")
        old = previous.backends.get(backend) if previous is not None else None
        if old is None:
            continue
        before = {
            test: index for index, shard in enumerate(old.shards, 1) for test in shard
        }
        for index, shard in enumerate(shards.shards, 1):
            for test in shard:
                if before.get(test) != index:
                    origin = before.get(test)
                    lines.append(
                        f"  {test}: "
                        + (f"shard {origin}" if origin else "new")
                        + f" -> shard {index}"
                    )
    return "\n".join(lines)


def configure_parser(parser: argparse.ArgumentParser) -> None:
    """Configure `plan-openvmm-test-shards`."""
    parser.description = (
        "Plan the shards of the OpenVMM VMM tests, which CI runs in parallel, "
        "from test duration reports (doc/ci.md#openvmm-vmm-test-shards)."
    )
    parser.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            f"an {OPENVMM_TEST_DURATIONS_NAME} or a directory to search for "
            "them, such as one that gh run download filled; repeatable"
        ),
    )
    parser.add_argument(
        "--seconds",
        type=shard_plans.named_seconds("TEST", "ttrpc::test_ttrpc_uefi_boot=9.4"),
        action="append",
        default=[],
        metavar="TEST=SECONDS",
        help=(
            "use this duration of TEST on every backend, such as an estimate "
            "of a test that no report measures; repeatable"
        ),
    )
    parser.add_argument(
        "--shards",
        type=shard_plans.backend_count,
        action="append",
        default=[],
        metavar="BACKEND=COUNT",
        help=(
            "split BACKEND's tests into COUNT shards instead of as many as the "
            "partition has; repeatable"
        ),
    )
    parser.add_argument(
        "--test-threads",
        type=shard_plans.backend_count,
        action="append",
        default=[],
        metavar="BACKEND=COUNT",
        help=(
            "model nextest's runs of BACKEND's tests with COUNT test threads, "
            "the logical processors of its runners, instead of as many as the "
            "partition has; repeatable"
        ),
    )
    parser.add_argument(
        "--partition",
        type=Path,
        default=PARTITION_PATH,
        metavar="PATH",
        help="the partition to update (default: the one that CI runs)",
    )
    parser.set_defaults(handler=run)


def run(args: argparse.Namespace) -> int:
    path: Path = args.partition
    estimates = dict(cast(list[tuple[str, float]], args.seconds))
    tests = {
        test for selection in OPENVMM_TEST_SELECTIONS.values() for test in selection
    }
    unknown = sorted(set(estimates) - tests)
    if unknown:
        raise ScriptError(
            "--seconds names tests that no sharded filter selects: "
            + ", ".join(unknown)
        )
    previous = load_partition(path) if path.exists() else None
    reports = cast(list[Path], args.report)
    samples, runs, processors = read_reports(reports)
    if reports and not samples:
        raise ScriptError(
            "no test duration report measures a test that passed in "
            + ", ".join(str(report) for report in reports)
        )
    partition = plan_partition(
        previous,
        samples=samples,
        runs=runs,
        estimates=estimates,
        counts=dict(cast(list[tuple[str, int]], args.shards)),
        test_threads=dict(cast(list[tuple[str, int]], args.test_threads)),
    )
    check_partition(partition, path)
    path.write_text(partition_json(partition), encoding="utf-8", newline="\n")
    print(describe_partition(previous, partition))
    for backend, shards in partition.backends.items():
        others = sorted(processors.get(backend, set()) - {shards.test_threads})
        if others:
            print(
                f"note: runners of the {backend} reports have "
                + ", ".join(str(count) for count in others)
                + f" logical processors, but the plan models {shards.test_threads} "
                f"test threads; pass --test-threads {backend}=COUNT to model another "
                "number"
            )
    print(f"Wrote {path}")
    return 0
