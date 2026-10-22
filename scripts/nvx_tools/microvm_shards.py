"""The shards of the default microVM suite, which CI runs in parallel.

doc/ci.md#microvm-test-shards describes the partition, how this module plans
it from scenario duration reports, and when to plan it again.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import re
import statistics
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from . import microvm_durations
from .ci import OPENVMM_TEST_BACKENDS
from .common import ScriptError, strict_json_object

PARTITION_PATH = Path(__file__).with_name("microvm_shards.json")
SCHEMA = "nvx-microvm-shards"
SCHEMA_VERSION = 1
# A change must shorten the longest shard, or the next longest where the
# longest stay alike, by at least this many tenths of a second, so that the
# noise of new medians does not reshuffle a partition that is balanced already.
MINIMUM_GAIN_TENTHS = 10
PLAN_ADVICE = (
    "plan the shards again with `nvx.py plan-microvm-shards` "
    "(doc/ci.md#microvm-test-shards)"
)


@dataclass(frozen=True)
class BackendShards:
    """One backend's partition of the default suite: each scenario's median
    duration in seconds, and the scenarios of each shard, in shard order."""

    seconds: Mapping[str, float]
    shards: tuple[tuple[str, ...], ...]

    def shard_seconds(self) -> tuple[float, ...]:
        """Return how long each shard's scenarios take in all."""
        return tuple(
            sum(_tenths(self.seconds[scenario]) for scenario in shard) / 10
            for shard in self.shards
        )


@dataclass(frozen=True)
class Partition:
    """The shards of every backend, and the CI runs, as `<run-id>-<attempt>`,
    whose reports gave the durations."""

    runs: tuple[str, ...]
    backends: Mapping[str, BackendShards]


def _tenths(seconds: float) -> int:
    return round(seconds * 10)


def parse_shard(value: str) -> tuple[int, int]:
    """Parse a --shard value, INDEX/COUNT, such as 1/2 for the first of two
    shards."""
    match = re.fullmatch(r"([1-9][0-9]*)/([1-9][0-9]*)", value)
    if match is None:
        raise argparse.ArgumentTypeError("must be INDEX/COUNT, such as 1/2")
    index, count = int(match.group(1)), int(match.group(2))
    if index > count:
        raise argparse.ArgumentTypeError("INDEX must be at most COUNT")
    return index, count


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _strings(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    items = cast(list[object], value)
    if not all(isinstance(item, str) for item in items):
        return None
    return tuple(cast(list[str], items))


def _object(value: object, keys: Collection[str]) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    document = cast(dict[str, object], value)
    return document if set(document) == set(keys) else None


def _backend_shards(value: object) -> BackendShards | None:
    document = _object(value, ("seconds", "shards"))
    if document is None:
        return None
    raw_seconds = document["seconds"]
    raw_shards = document["shards"]
    if not isinstance(raw_seconds, dict) or not isinstance(raw_shards, list):
        return None
    seconds: dict[str, float] = {}
    for scenario, duration in cast(dict[str, object], raw_seconds).items():
        number = _number(duration)
        if number is None or number < 0:
            return None
        seconds[scenario] = number
    shards: list[tuple[str, ...]] = []
    for raw_shard in cast(list[object], raw_shards):
        shard = _object(raw_shard, ("seconds", "scenarios"))
        if shard is None or _number(shard["seconds"]) is None:
            return None
        scenarios = _strings(shard["scenarios"])
        if scenarios is None:
            return None
        shards.append(scenarios)
    return BackendShards(seconds, tuple(shards))


def load_partition(path: Path = PARTITION_PATH) -> Partition:
    """Read a partition, failing unless its structure is valid; whether it
    partitions the default suite is check_partition()'s question."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ScriptError(f"{path} does not exist; {PLAN_ADVICE}") from None
    try:
        value: object = json.loads(text, object_pairs_hook=strict_json_object)
    except ValueError as error:
        raise ScriptError(f"{path} is not valid JSON: {error}") from error
    document = _object(value, ("schema", "schema_version", "runs", "backends"))
    if (
        document is None
        or document["schema"] != SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise ScriptError(
            f"{path} is not an {SCHEMA} document of schema version {SCHEMA_VERSION}"
        )
    runs = _strings(document["runs"])
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


def partition_problems(partition: Partition, suite: Sequence[str]) -> list[str]:
    """Return how a partition fails to put each scenario of the default suite
    in exactly one shard of every backend, with its duration."""
    problems: list[str] = []
    expected = set(suite)
    for backend in sorted(set(partition.backends) - set(OPENVMM_TEST_BACKENDS)):
        problems.append(f"{backend} is not a backend")
    for backend in OPENVMM_TEST_BACKENDS:
        shards = partition.backends.get(backend)
        if shards is None:
            problems.append(f"{backend} has no shards")
            continue
        if not shards.shards:
            problems.append(f"{backend} has no shards")
        placements: dict[str, list[int]] = {}
        for index, shard in enumerate(shards.shards, 1):
            if not shard:
                problems.append(f"{backend} shard {index} is empty")
            for scenario in shard:
                placements.setdefault(scenario, []).append(index)
        for scenario in suite:
            found = placements.get(scenario, [])
            if not found:
                problems.append(f"{backend}: {scenario} is in no shard")
            elif len(found) > 1:
                problems.append(
                    f"{backend}: {scenario} is in more than one shard: "
                    + ", ".join(str(index) for index in found)
                )
        for scenario in sorted(set(placements) - expected):
            problems.append(f"{backend}: {scenario} is not a default scenario")
        for scenario in suite:
            if scenario not in shards.seconds:
                problems.append(f"{backend}: {scenario} has no duration")
        for scenario in sorted(set(shards.seconds) - expected):
            problems.append(
                f"{backend}: {scenario} has a duration but is not a default scenario"
            )
    return problems


def check_partition(
    partition: Partition, suite: Sequence[str], path: Path = PARTITION_PATH
) -> None:
    """Fail unless the partition puts each scenario of the default suite in
    exactly one shard of every backend."""
    problems = partition_problems(partition, suite)
    if problems:
        raise ScriptError(
            f"{path} does not put each default microVM scenario in exactly one "
            f"shard: {'; '.join(problems)}; {PLAN_ADVICE}"
        )


def shard_scenarios(
    partition: Partition,
    backend: str,
    shard: tuple[int, int],
    suite: Sequence[str],
    path: Path = PARTITION_PATH,
) -> tuple[str, ...]:
    """Return the scenarios of shard INDEX of COUNT of a backend's default
    suite, in suite order, once the partition is checked and has COUNT shards
    for the backend."""
    check_partition(partition, suite, path)
    index, count = shard
    shards = partition.backends[backend].shards
    if count != len(shards):
        raise ScriptError(
            f"{path} splits the {backend} suite into {len(shards)} shards, but "
            f"this run is shard {index} of {count}; CI must run one job for each "
            "shard (doc/ci.md#microvm-test-shards)"
        )
    selected = set(shards[index - 1])
    return tuple(scenario for scenario in suite if scenario in selected)


def _report_records(path: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value: object = json.loads(line, object_pairs_hook=strict_json_object)
        except ValueError as error:
            raise ScriptError(f"{path}:{number} is not valid JSON: {error}") from error
        if not isinstance(value, dict):
            raise ScriptError(f"{path}:{number} is not a JSON object")
        records.append(cast(dict[str, object], value))
    return records


def _report_paths(paths: Iterable[Path]) -> list[Path]:
    found: dict[Path, None] = {}
    for path in paths:
        if path.is_dir():
            for report in sorted(path.rglob(microvm_durations.REPORT_NAME)):
                found[report.resolve()] = None
        elif path.is_file():
            found[path.resolve()] = None
        else:
            raise ScriptError(f"{path} is neither a report nor a directory")
    return list(found)


def read_reports(
    paths: Iterable[Path], *, suite: Collection[str], processors: Sequence[int]
) -> tuple[dict[str, dict[str, list[float]]], set[str]]:
    """Return each backend's samples of the duration of each scenario of the
    default suite, and the CI runs that they come from.

    A sample is one report's time for every execution of a scenario, such as
    the four processor counts of console-exit, when none of them failed. Only
    the reports of the default suite count: the Alpine guest on the default
    kernel with the default processor counts, of a run that ended, failed or
    not, since a run that was killed may have recorded part of its last
    scenario.
    """
    samples: dict[str, dict[str, list[float]]] = {}
    runs: set[str] = set()
    headers: set[str] = set()
    for path in _report_paths(paths):
        records = _report_records(path)
        if not records:
            continue
        header = records[0]
        if (
            header.get("record") != "run"
            or header.get("schema") != microvm_durations.SCHEMA
            or header.get("schema_version") != microvm_durations.SCHEMA_VERSION
        ):
            raise ScriptError(
                f"{path} is not a scenario duration report of schema version "
                f"{microvm_durations.SCHEMA_VERSION}"
            )
        backend = header.get("backend")
        if (
            header.get("guest") != "alpine"
            or header.get("kernel") != "default"
            or header.get("processors") != list(processors)
            or not isinstance(backend, str)
            or backend not in OPENVMM_TEST_BACKENDS
            or not any(record.get("record") == "teardown" for record in records)
        ):
            continue
        # The same report found twice counts once.
        identity = json.dumps(header, sort_keys=True)
        if identity in headers:
            continue
        headers.add(identity)
        executions: dict[str, list[dict[str, object]]] = {}
        for record in records:
            scenario = record.get("scenario")
            if record.get("record") == "scenario" and scenario in suite:
                executions.setdefault(cast(str, scenario), []).append(record)
        measured = False
        for scenario, records_of_scenario in executions.items():
            durations = [
                _number(record.get("seconds")) for record in records_of_scenario
            ]
            if any(
                record.get("outcome") != "passed" for record in records_of_scenario
            ) or any(duration is None for duration in durations):
                continue
            samples.setdefault(backend, {}).setdefault(scenario, []).append(
                sum(cast(list[float], durations))
            )
            measured = True
        github = header.get("github")
        if measured and isinstance(github, dict):
            job = cast(dict[str, object], github)
            run_id, attempt = job.get("run_id"), job.get("run_attempt")
            if isinstance(run_id, str) and isinstance(attempt, str):
                runs.add(f"{run_id}-{attempt}")
    return samples, runs


def _changes(
    scenarios: Sequence[str], shard_of: Mapping[str, int], count: int
) -> Iterator[tuple[tuple[str, int], ...]]:
    """Yield every move of a scenario to another shard, and every swap of two
    scenarios of different shards, as the scenarios' new shards."""
    for scenario in scenarios:
        for shard in range(count):
            if shard != shard_of[scenario]:
                yield ((scenario, shard),)
    for first, second in itertools.combinations(scenarios, 2):
        if shard_of[first] != shard_of[second]:
            yield ((first, shard_of[second]), (second, shard_of[first]))


def _gain(current: Sequence[int], candidate: Sequence[int]) -> int:
    """Return by how much a candidate's totals, longest first, undercut the
    current ones where they first differ; negative if they exceed them."""
    for before, after in zip(current, candidate, strict=True):
        if before != after:
            return before - after
    return 0


def plan_shards(
    seconds: Mapping[str, float],
    count: int,
    previous: Sequence[Collection[str]] = (),
) -> tuple[tuple[str, ...], ...]:
    """Split scenarios of the given durations into `count` balanced shards.

    Each scenario starts in its shard of `previous`, the partition to update;
    the others go, longest first, to the shard that takes the least time so
    far. A shard that is still empty then takes the longest scenario of the
    longest shard that has more than one, since no move into it may shorten
    a shard enough, as when its candidates take no time. The plan then moves
    a scenario to another shard, or swaps two of different shards, while that
    shortens the longest shard by MINIMUM_GAIN_TENTHS or more, comparing the
    next longest where the longest stay alike, and takes the best such change
    each time; no such change empties a shard. Each shard lists its scenarios
    in name order.
    """
    tenths = {scenario: _tenths(duration) for scenario, duration in seconds.items()}
    scenarios = sorted(tenths)
    if not 1 <= count <= len(scenarios):
        raise ScriptError(
            f"cannot split {len(scenarios)} scenarios into {count} shards"
        )
    shard_of: dict[str, int] = {}
    for shard, members in enumerate(previous[:count]):
        for scenario in sorted(members):
            if scenario in tenths and scenario not in shard_of:
                shard_of[scenario] = shard
    totals = [0] * count
    for scenario, shard in shard_of.items():
        totals[shard] += tenths[scenario]
    for scenario in sorted(
        (scenario for scenario in scenarios if scenario not in shard_of),
        key=lambda scenario: (-tenths[scenario], scenario),
    ):
        shard = min(range(count), key=lambda index: (totals[index], index))
        shard_of[scenario] = shard
        totals[shard] += tenths[scenario]
    for shard in range(count):
        sizes = Counter(shard_of.values())
        if sizes[shard]:
            continue
        donor = max(
            (index for index in range(count) if sizes[index] > 1),
            key=lambda index: (totals[index], -index),
        )
        scenario = min(
            (scenario for scenario in scenarios if shard_of[scenario] == donor),
            key=lambda scenario: (-tenths[scenario], scenario),
        )
        shard_of[scenario] = shard
        totals[donor] -= tenths[scenario]
        totals[shard] += tenths[scenario]
    while True:
        current = sorted(totals, reverse=True)
        best: tuple[list[int], tuple[tuple[str, int], ...], list[int]] | None = None
        for change in _changes(scenarios, shard_of, count):
            trial = list(totals)
            for scenario, shard in change:
                trial[shard_of[scenario]] -= tenths[scenario]
                trial[shard] += tenths[scenario]
            candidate = sorted(trial, reverse=True)
            if _gain(current, candidate) >= MINIMUM_GAIN_TENTHS and (
                best is None or candidate < best[0]
            ):
                best = (candidate, change, trial)
        if best is None:
            break
        for scenario, shard in best[1]:
            shard_of[scenario] = shard
        totals = best[2]
    return tuple(
        tuple(scenario for scenario in scenarios if shard_of[scenario] == shard)
        for shard in range(count)
    )


def _run_order(run: str) -> tuple[int, ...]:
    return tuple(int(part) if part.isdigit() else 0 for part in run.split("-"))


def plan_partition(
    previous: Partition | None,
    suite: Sequence[str],
    *,
    samples: Mapping[str, Mapping[str, Sequence[float]]],
    runs: Collection[str],
    estimates: Mapping[str, float],
    counts: Mapping[str, int],
) -> Partition:
    """Plan every backend's shards of the default suite.

    A scenario's duration is its estimate, if given, or else the median of
    the backend's samples, to a tenth of a second, or else its duration in
    `previous`. A backend keeps its number of shards unless `counts` changes
    it, and its scenarios start in their shards of `previous`.
    """
    backends: dict[str, BackendShards] = {}
    missing: list[str] = []
    for backend in OPENVMM_TEST_BACKENDS:
        old = previous.backends.get(backend) if previous is not None else None
        measured = samples.get(backend, {})
        seconds: dict[str, float] = {}
        for scenario in suite:
            if scenario in estimates:
                seconds[scenario] = round(estimates[scenario], 1)
            elif measured.get(scenario):
                seconds[scenario] = round(statistics.median(measured[scenario]), 1)
            elif old is not None and scenario in old.seconds:
                seconds[scenario] = old.seconds[scenario]
            else:
                missing.append(f"{scenario} on {backend}")
        count = counts.get(backend, len(old.shards) if old is not None else 0)
        if count == 0:
            raise ScriptError(
                f"the partition has no {backend} shards; pass --shards {backend}=COUNT"
            )
        if missing:
            continue
        previous_shards = old.shards if old is not None else ()
        backends[backend] = BackendShards(
            seconds, plan_shards(seconds, count, previous_shards)
        )
    if missing:
        raise ScriptError(
            "no report measures, and the partition has no duration of, "
            + ", ".join(missing)
            + "; pass --report with a report that measures them, or --seconds "
            "SCENARIO=SECONDS with an estimate"
        )
    planned_runs = (
        tuple(sorted(runs, key=_run_order))
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
                "seconds": {
                    scenario: shards.seconds[scenario]
                    for scenario in sorted(shards.seconds)
                },
                "shards": [
                    {"seconds": total, "scenarios": list(shard)}
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
    """Return each backend's shards, with their durations and the scenarios
    that changed shard."""
    lines: list[str] = []
    for backend, shards in partition.backends.items():
        totals = shards.shard_seconds()
        lines.append(
            f"{backend}: {len(shards.shards)} shards, "
            f"{sum(_tenths(total) for total in totals) / 10:.1f} s in all"
        )
        for index, (shard, total) in enumerate(
            zip(shards.shards, totals, strict=True), 1
        ):
            lines.append(f"  shard {index}: {total:.1f} s, {len(shard)} scenarios")
        old = previous.backends.get(backend) if previous is not None else None
        if old is None:
            continue
        before = {
            scenario: index
            for index, shard in enumerate(old.shards, 1)
            for scenario in shard
        }
        for index, shard in enumerate(shards.shards, 1):
            for scenario in shard:
                if before.get(scenario) != index:
                    origin = before.get(scenario)
                    lines.append(
                        f"  {scenario}: "
                        + (f"shard {origin}" if origin else "new")
                        + f" -> shard {index}"
                    )
    return "\n".join(lines)


def _estimate(value: str) -> tuple[str, float]:
    scenario, separator, seconds = value.partition("=")
    try:
        duration = float(seconds)
    except ValueError:
        duration = -1.0
    if not separator or not scenario or not 0 <= duration < math.inf:
        raise argparse.ArgumentTypeError("must be SCENARIO=SECONDS, such as smp=20")
    return scenario, duration


def _shard_count(value: str) -> tuple[str, int]:
    backend, separator, count = value.partition("=")
    if (
        not separator
        or backend not in OPENVMM_TEST_BACKENDS
        or not count.isdigit()
        or int(count) < 1
    ):
        raise argparse.ArgumentTypeError(
            "must be BACKEND=COUNT, such as whp=2, for a backend of "
            + ", ".join(OPENVMM_TEST_BACKENDS)
        )
    return backend, int(count)


def configure_parser(
    parser: argparse.ArgumentParser,
    *,
    suite: Callable[[], Sequence[str]],
    processors: Sequence[int],
) -> None:
    """Configure `plan-microvm-shards` for the default suite that `suite`
    returns, with the default processor counts."""
    parser.description = (
        "Plan the shards of the default microVM suite, which CI runs in "
        "parallel, from scenario duration reports (doc/ci.md#microvm-test-shards)."
    )
    parser.add_argument(
        "--report",
        type=Path,
        action="append",
        default=[],
        metavar="PATH",
        help=(
            f"a {microvm_durations.REPORT_NAME} or a directory to search for "
            "them, such as one that gh run download filled; repeatable"
        ),
    )
    parser.add_argument(
        "--seconds",
        type=_estimate,
        action="append",
        default=[],
        metavar="SCENARIO=SECONDS",
        help=(
            "use this duration of SCENARIO on every backend, such as an "
            "estimate of a scenario that no report measures; repeatable"
        ),
    )
    parser.add_argument(
        "--shards",
        type=_shard_count,
        action="append",
        default=[],
        metavar="BACKEND=COUNT",
        help=(
            "split BACKEND's suite into COUNT shards instead of as many as "
            "the partition has; repeatable"
        ),
    )
    parser.add_argument(
        "--partition",
        type=Path,
        default=PARTITION_PATH,
        metavar="PATH",
        help="the partition to update (default: the one that CI runs)",
    )

    def handler(args: argparse.Namespace) -> int:
        return run(args, suite=suite(), processors=processors)

    parser.set_defaults(handler=handler)


def run(
    args: argparse.Namespace, *, suite: Sequence[str], processors: Sequence[int]
) -> int:
    path: Path = args.partition
    estimates = dict(cast(list[tuple[str, float]], args.seconds))
    unknown = sorted(set(estimates) - set(suite))
    if unknown:
        raise ScriptError(
            "--seconds names scenarios outside the default suite: " + ", ".join(unknown)
        )
    previous = load_partition(path) if path.exists() else None
    reports = cast(list[Path], args.report)
    samples, runs = read_reports(reports, suite=suite, processors=processors)
    if reports and not samples:
        raise ScriptError(
            "no report of the default microVM suite measures a scenario in "
            + ", ".join(str(report) for report in reports)
        )
    partition = plan_partition(
        previous,
        suite,
        samples=samples,
        runs=runs,
        estimates=estimates,
        counts=dict(cast(list[tuple[str, int]], args.shards)),
    )
    check_partition(partition, suite, path)
    path.write_text(partition_json(partition), encoding="utf-8", newline="\n")
    print(describe_partition(previous, partition))
    print(f"Wrote {path}")
    return 0
