"""Reuse of the guest images that a pull request's CI run built.

GitHub scopes the caches that a pull request's runs save to the pull request,
so the dev push that merges it misses them and would rebuild the guest images
that the pull request already built. The build-guest-artifacts action
therefore records its cache keys and the SHA-256 of each guest image file in
the guest artifact record, which the artifacts job uploads with the images.
The push looks up the latest run of its workflow for the head of the pull
request that it merged, from the same repository and never from a fork, and,
when an image missed its cache, installs every image from that run's artifact
once the artifact matches the digest that GitHub recorded for it, the
record's keys equal the push's own, and the files match the record, their
provenance, and the push's sources. Any other outcome, or a time limit, leaves
the images to the action's builds, so reuse never fails a run and never
installs an unverified file.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import FrameType
from typing import Protocol, cast

from .build_constants import DockerBuildConstants
from .common import (
    ScriptError,
    credential_safe_opener,
    require_file,
    sha256_file,
    strict_json_object,
)
from .release import GITHUB_API_VERSION, validate_guest_artifacts

RECORD_NAME = "guest-artifacts.json"
RECORD_FORMAT = 1
# The files that the record describes and that a push installs. The action
# formats the Ubuntu sandbox scratch template in every run, so it is not one.
IMAGE_NAMES = DockerBuildConstants.ALL_GUEST_ARTIFACT_NAMES
GITHUB_API_URL = "https://api.github.com"
# A cold build takes three to eleven minutes, so a reuse that takes longer than
# this saves little.
REUSE_TIMEOUT_SECONDS = 240.0
_REQUEST_TIMEOUT_SECONDS = 30.0
_CHUNK_BYTES = 1024 * 1024
_RECORD_MAX_BYTES = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SHA256_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_REUSE = "Guest artifact reuse"
_REHEARSAL = "Guest artifact reuse rehearsal"


class ReuseRefused(ScriptError):
    """A reason to build the guest images rather than reuse a run's.

    An expected reason, such as a push that merged no same-repository pull
    request run or different cache keys, is a normal outcome; any other
    suggests a fault, which CI reports as a warning.
    """

    def __init__(self, reason: str, *, expected: bool = False) -> None:
        super().__init__(reason)
        self.expected = expected


class GitHubApi(Protocol):
    """The GitHub REST API requests that reuse makes."""

    def get(self, endpoint: str) -> object:
        """Return the JSON document at `endpoint`, relative to the API root."""
        ...

    def download(self, endpoint: str, destination: Path) -> None:
        """Write the content at `endpoint` to `destination`."""
        ...


class RestApi:
    """Reads the GitHub REST API with a token, until a monotonic deadline.

    Its opener drops the token when a download redirects to another origin,
    as artifact downloads do to their storage.
    """

    def __init__(
        self,
        token: str,
        deadline: float,
        *,
        url: str = GITHUB_API_URL,
    ) -> None:
        self._token = token
        self._deadline = deadline
        self._url = url.rstrip("/")
        self._opener = credential_safe_opener()

    def _timeout(self, endpoint: str) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise ReuseRefused(f"reuse ran out of time before GET {endpoint}")
        return min(_REQUEST_TIMEOUT_SECONDS, remaining)

    def _request(self, endpoint: str) -> urllib.request.Request:
        return urllib.request.Request(
            f"{self._url}/{endpoint}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "nvx-guest-artifact-reuse",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )

    def get(self, endpoint: str) -> object:
        try:
            with self._opener.open(
                self._request(endpoint), timeout=self._timeout(endpoint)
            ) as response:
                return json.load(response)
        except (OSError, ValueError) as error:
            raise _request_refusal(endpoint, error) from error

    def download(self, endpoint: str, destination: Path) -> None:
        try:
            with (
                self._opener.open(
                    self._request(endpoint), timeout=self._timeout(endpoint)
                ) as response,
                destination.open("wb") as output,
            ):
                while chunk := response.read(_CHUNK_BYTES):
                    output.write(chunk)
                    if time.monotonic() > self._deadline:
                        raise ReuseRefused(
                            f"reuse ran out of time while downloading {endpoint}"
                        )
        except OSError as error:
            raise _request_refusal(endpoint, error) from error


def _request_refusal(endpoint: str, error: OSError | ValueError) -> ReuseRefused:
    if isinstance(error, urllib.error.HTTPError):
        # An HTTP error holds the response open.
        error.close()
        return ReuseRefused(f"GET {endpoint} failed with HTTP {error.code}")
    return ReuseRefused(f"GET {endpoint} failed: {error}")


@dataclass(frozen=True)
class PullRequestRun:
    """A pull_request run of the workflow, from the repository itself."""

    id: int
    url: str


@dataclass(frozen=True)
class RunArtifact:
    """An unexpired artifact of a workflow run."""

    id: int
    name: str
    digest: str | None


@dataclass(frozen=True)
class ReuseRequest:
    """What to reuse, and for which push or rehearsal.

    A push names its merge commit, whose second parent is the head of the
    pull request that it merged; a rehearsal names that head itself.
    """

    repository: str
    workflow_ref: str
    artifact: str
    keys: Mapping[str, str]
    commit: str | None = None
    head_sha: str | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class ReuseOutcome:
    """What reuse did, and why; `level` annotates a fallback to building."""

    reused: bool
    heading: str
    status: str
    detail: str
    level: str | None = None

    def summary(self) -> str:
        return f"### {self.heading}: {self.status}\n{self.detail}\n"


def _object(value: object, description: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReuseRefused(f"GitHub returned an invalid {description}")
    return cast(dict[str, object], value)


def _objects(value: object, description: str) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ReuseRefused(f"GitHub returned an invalid {description} list")
    return [_object(item, description) for item in cast(list[object], value)]


def _text(document: dict[str, object], field: str, description: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise ReuseRefused(f"GitHub returned a {description} without a {field}")
    return value


def _integer(document: dict[str, object], field: str, description: str) -> int:
    value = document.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReuseRefused(f"GitHub returned a {description} without a {field}")
    return value


def _repository_name(value: object) -> str | None:
    """Return the full name of a repository document; a deleted fork's is
    null."""
    if not isinstance(value, dict):
        return None
    name = cast(dict[str, object], value).get("full_name")
    return name if isinstance(name, str) else None


def _cache_keys(document: object) -> dict[str, str]:
    if not isinstance(document, dict) or not document:
        raise ScriptError("cache keys must be a nonempty JSON object")
    keys: dict[str, str] = {}
    for name, value in cast(dict[str, object], document).items():
        if not name or not isinstance(value, str) or not value:
            raise ScriptError(f"cache key {name!r} must be a nonempty string")
        keys[name] = value
    return keys


def parse_cache_keys(text: str) -> dict[str, str]:
    """Parse a JSON object of exact cache keys by name."""
    try:
        document: object = json.loads(text, object_pairs_hook=strict_json_object)
    except ValueError as error:
        raise ScriptError(f"cache keys are not JSON: {error}") from error
    return _cache_keys(document)


def record_guest_artifacts(directory: Path, keys: Mapping[str, str]) -> Path:
    """Write the guest artifact record of the images in `directory`: this
    run's cache keys and the SHA-256 of each image file, which a push checks
    before it reuses them."""
    files = {
        name: sha256_file(require_file(directory / name, f"guest artifact {name}"))
        for name in IMAGE_NAMES
    }
    document = {
        "format": RECORD_FORMAT,
        "keys": dict(sorted(_cache_keys(dict(keys)).items())),
        "files": files,
    }
    path = directory / RECORD_NAME
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def _parse_record(contents: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """Return the cache keys and the image file digests of a record."""
    try:
        document: object = json.loads(
            contents.decode("utf-8"), object_pairs_hook=strict_json_object
        )
        if not isinstance(document, dict):
            raise ScriptError("it is not a JSON object")
        record = cast(dict[str, object], document)
        if type(record.get("format")) is not int or record["format"] != RECORD_FORMAT:
            raise ScriptError(f"its format is not {RECORD_FORMAT}")
        keys = _cache_keys(record.get("keys"))
        files = record.get("files")
        if not isinstance(files, dict):
            raise ScriptError("it lists no files")
        digests = cast(dict[str, object], files)
    except (ScriptError, ValueError) as error:
        raise ReuseRefused(f"the {RECORD_NAME} record is invalid: {error}") from error
    images: dict[str, str] = {}
    for name in IMAGE_NAMES:
        digest = digests.get(name)
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ReuseRefused(f"the {RECORD_NAME} record gives no SHA-256 of {name}")
        images[name] = digest
    return keys, images


def workflow_path(workflow_ref: str, repository: str) -> str:
    """Return the path of the workflow that `workflow_ref`, the
    GITHUB_WORKFLOW_REF of a run of `repository`, names."""
    reference, separator, _ = workflow_ref.partition("@")
    path = reference.removeprefix(f"{repository}/")
    if (
        not separator
        or path == reference
        or PurePosixPath(path).parent != PurePosixPath(".github/workflows")
    ):
        raise ReuseRefused(f"{workflow_ref!r} names no workflow of {repository}")
    return path


def merged_head(api: GitHubApi, repository: str, commit: str) -> str:
    """Return the head of the pull request that the merge commit `commit`
    merged: its second parent."""
    document = _object(api.get(f"repos/{repository}/git/commits/{commit}"), "commit")
    parents = [
        _text(parent, "sha", "commit parent")
        for parent in _objects(document.get("parents"), "commit parent")
    ]
    if len(parents) != 2:
        raise ReuseRefused(
            f"`{commit}` is not the merge commit of a pull request", expected=True
        )
    return parents[1]


def latest_pull_request_run(
    api: GitHubApi,
    repository: str,
    workflow: str,
    head_sha: str,
) -> PullRequestRun:
    """Return the latest pull_request run of `workflow` for `head_sha` whose
    head is in `repository`; a fork's run never qualifies."""
    query = urllib.parse.urlencode(
        {"event": "pull_request", "head_sha": head_sha, "per_page": 100}
    )
    name = urllib.parse.quote(PurePosixPath(workflow).name, safe="")
    document = _object(
        api.get(f"repos/{repository}/actions/workflows/{name}/runs?{query}"),
        "workflow run list",
    )
    candidates: list[tuple[int, int, PullRequestRun]] = []
    other_repositories = 0
    for run in _objects(document.get("workflow_runs"), "workflow run"):
        if (
            run.get("event") != "pull_request"
            or run.get("head_sha") != head_sha
            or _text(run, "path", "workflow run").partition("@")[0] != workflow
        ):
            continue
        if (
            _repository_name(run.get("head_repository")) != repository
            or _repository_name(run.get("repository")) != repository
        ):
            other_repositories += 1
            continue
        run_id = _integer(run, "id", "workflow run")
        candidates.append(
            (
                _integer(run, "run_number", "workflow run"),
                run_id,
                PullRequestRun(run_id, _text(run, "html_url", "workflow run")),
            )
        )
    if not candidates:
        ignored = (
            f"; {other_repositories} from other repositories never qualify"
            if other_repositories
            else ""
        )
        raise ReuseRefused(
            f"no pull request run of `{workflow}` from {repository} built "
            f"`{head_sha}`{ignored}",
            expected=True,
        )
    return max(candidates, key=lambda candidate: candidate[:2])[2]


def retained_artifact(
    api: GitHubApi,
    repository: str,
    run: PullRequestRun,
    name: str,
) -> RunArtifact:
    """Return the newest unexpired artifact named `name` of `run`."""
    query = urllib.parse.urlencode({"name": name, "per_page": 100})
    document = _object(
        api.get(f"repos/{repository}/actions/runs/{run.id}/artifacts?{query}"),
        "artifact list",
    )
    candidates: list[tuple[str, int, RunArtifact]] = []
    for artifact in _objects(document.get("artifacts"), "artifact"):
        workflow_run = _object(artifact.get("workflow_run"), "artifact run")
        if (
            artifact.get("name") != name
            or artifact.get("expired") is not False
            or workflow_run.get("id") != run.id
        ):
            continue
        artifact_id = _integer(artifact, "id", "artifact")
        digest = artifact.get("digest")
        candidates.append(
            (
                _text(artifact, "created_at", "artifact"),
                artifact_id,
                RunArtifact(
                    artifact_id, name, digest if isinstance(digest, str) else None
                ),
            )
        )
    if not candidates:
        raise ReuseRefused(
            f"[run {run.id}]({run.url}) has no unexpired `{name}` artifact",
            expected=True,
        )
    return max(candidates, key=lambda candidate: candidate[:2])[2]


def _download(
    api: GitHubApi,
    repository: str,
    artifact: RunArtifact,
    archive: Path,
) -> None:
    # The digest that GitHub took when the run uploaded the artifact is the
    # only check of the archive that doesn't come from inside it.
    digest = _SHA256_DIGEST.fullmatch(artifact.digest or "")
    if digest is None:
        raise ReuseRefused(
            f"artifact {artifact.id} has no SHA-256 digest, but {artifact.digest!r}"
        )
    api.download(f"repos/{repository}/actions/artifacts/{artifact.id}/zip", archive)
    if sha256_file(archive) != digest.group(1):
        raise ReuseRefused(
            f"artifact {artifact.id} does not match its digest {artifact.digest}"
        )


def _extract(archive: Path, staging: Path) -> dict[str, str]:
    """Extract the image files of the artifact `archive` into `staging`,
    check each against the SHA-256 that the artifact's record gives, and
    return the record's cache keys."""
    try:
        with zipfile.ZipFile(archive) as bundle:
            members = {
                member.filename: member
                for member in bundle.infolist()
                if not member.is_dir()
            }
            record = members.get(RECORD_NAME)
            if record is None:
                # As those of runs from before the record are.
                raise ReuseRefused(
                    f"the artifact has no {RECORD_NAME} record", expected=True
                )
            if record.file_size > _RECORD_MAX_BYTES:
                raise ReuseRefused(f"the artifact's {RECORD_NAME} record is too large")
            keys, digests = _parse_record(bundle.read(record))
            for name in IMAGE_NAMES:
                member = members.get(name)
                if member is None:
                    raise ReuseRefused(f"the artifact has no {name}")
                digest = hashlib.sha256()
                with (
                    bundle.open(member) as source,
                    (staging / name).open("wb") as output,
                ):
                    while chunk := source.read(_CHUNK_BYTES):
                        output.write(chunk)
                        digest.update(chunk)
                if digest.hexdigest() != digests[name]:
                    raise ReuseRefused(
                        f"the artifact's {name} does not match the SHA-256 that "
                        "its record gives"
                    )
    except ScriptError:
        raise
    # zipfile reports a corrupt member as BadZipFile, a truncated one as
    # EOFError, an unknown compression as NotImplementedError, and an
    # encrypted one as RuntimeError.
    except (
        zipfile.BadZipFile,
        EOFError,
        NotImplementedError,
        RuntimeError,
        ValueError,
    ) as error:
        raise ReuseRefused(f"the artifact is not a valid ZIP archive: {error}") from (
            error
        )
    return keys


def _key_differences(
    recorded: Mapping[str, str],
    expected: Mapping[str, str],
) -> list[str]:
    return sorted(
        name
        for name in recorded.keys() | expected.keys()
        if recorded.get(name) != expected.get(name)
    )


def _install(staging: Path, destination: Path, names: Sequence[str]) -> None:
    """Move the files `names` from `staging` into `destination`, in place of
    any there, or leave `destination` as it was.

    Each move is noted before it happens, so that the rollback also undoes a
    move that an exception interrupted right after the rename.
    """
    replaced = staging / ".replaced"
    replaced.mkdir()
    moving: list[str] = []
    installing: list[str] = []
    try:
        for name in names:
            target = destination / name
            if os.path.lexists(target):
                moving.append(name)
                os.replace(target, replaced / name)
            installing.append(name)
            os.replace(staging / name, target)
    except BaseException as error:
        # Whatever is at a target being installed is either its new file or
        # nothing, since its old one, if any, has moved aside.
        for name in installing:
            (destination / name).unlink(missing_ok=True)
        for name in moving:
            if os.path.lexists(replaced / name):
                os.replace(replaced / name, destination / name)
        if isinstance(error, OSError):
            raise ReuseRefused(f"the images could not be installed: {error}") from error
        raise


@contextlib.contextmanager
def _time_limit(deadline: float | None) -> Generator[None]:
    """Interrupt the work in the block with ReuseRefused once the
    time.monotonic() value `deadline` passes.

    The request timeouts bound each wait for the network, but not a download
    that keeps trickling in or the checks after it, so on POSIX an interval
    timer raises wherever the main thread is. Elsewhere, only the request
    timeouts and the download's own deadline checks apply.
    """
    if deadline is None:
        yield
        return
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise ReuseRefused("reuse ran out of time")
    if sys.platform == "win32":
        yield
        return
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def expire(_signal: int, _frame: FrameType | None) -> None:
        if armed:
            raise ReuseRefused("reuse ran out of time")

    armed = True
    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        # A signal that arrives once the block has ended must not raise in
        # place of the restoration of the previous handler.
        armed = False
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _sentence(text: str) -> str:
    text = text.rstrip(".")
    return f"{text[:1].upper()}{text[1:]}"


def _fallback(dry_run: bool) -> str:
    if dry_run:
        return (
            "a push that merged this head would build the guest images that "
            "missed its cache"
        )
    return "the action builds the guest images that missed the cache"


def _checked_artifact(api: GitHubApi, request: ReuseRequest, staging: Path) -> str:
    """Select the artifact of the latest run for the pull request's head,
    download it into `staging`, check the images in it, and describe it."""
    workflow = workflow_path(request.workflow_ref, request.repository)
    if request.head_sha is not None:
        head_sha = request.head_sha
    elif request.commit is not None:
        head_sha = merged_head(api, request.repository, request.commit)
    else:
        raise ReuseRefused("neither a merge commit nor a head was given")
    run = latest_pull_request_run(api, request.repository, workflow, head_sha)
    artifact = retained_artifact(api, request.repository, run, request.artifact)
    source = (
        f"artifact `{artifact.name}` of [run {run.id}]({run.url}), the latest "
        f"run of `{workflow}` for pull request head `{head_sha}`"
    )
    archive = staging / "artifact.zip"
    _download(api, request.repository, artifact, archive)
    differences = _key_differences(_extract(archive, staging), request.keys)
    if differences:
        raise ReuseRefused(
            f"{source} recorded other cache keys for {', '.join(differences)}",
            expected=True,
        )
    try:
        validate_guest_artifacts(staging)
    except ReuseRefused:
        raise
    except (ScriptError, OSError) as error:
        raise ReuseRefused(
            f"the images of {source} do not match their provenance or "
            f"this checkout: {error}"
        ) from error
    return source


def reuse_guest_artifacts(
    api: GitHubApi,
    request: ReuseRequest,
    destination: Path,
    *,
    deadline: float | None = None,
) -> ReuseOutcome:
    """Install the guest images from the artifact of the latest run for the
    pull request's head when `destination` lacks any of them, or explain why
    not, giving up on the artifact at the time.monotonic() value `deadline`.

    A cache restore that misses leaves its files absent, but one that fails
    partway can leave a truncated file and report a miss too, so reuse
    replaces every image file with its checked copy rather than only the
    absent ones; the images that the cache did restore have the same keys. A
    rehearsal checks the artifact in the same way but installs nothing.
    """
    heading = _REHEARSAL if request.dry_run else _REUSE
    absent = [name for name in IMAGE_NAMES if not (destination / name).exists()]
    if not absent and not request.dry_run:
        return ReuseOutcome(
            False,
            heading,
            "not needed",
            "Every guest image was restored from the cache.",
        )
    try:
        destination.mkdir(parents=True, exist_ok=True)
        # Beside the destination, so that installing a file renames it.
        staging = Path(
            tempfile.mkdtemp(prefix=".guest-artifact-reuse-", dir=destination)
        )
        try:
            with _time_limit(deadline):
                source = _checked_artifact(api, request, staging)
            if request.dry_run:
                return ReuseOutcome(
                    False,
                    heading,
                    "would reuse",
                    "A push that merged this head would install the guest images "
                    f"from {source}: its cache keys, the SHA-256 of each file, and "
                    "their provenance check out.",
                )
            # Outside the time limit, whose timer must not cut a rollback short.
            _install(staging, destination, IMAGE_NAMES)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    except (ScriptError, OSError) as error:
        expected = isinstance(error, ReuseRefused) and error.expected
        return ReuseOutcome(
            False,
            heading,
            "build",
            f"{_sentence(str(error))}, so {_fallback(request.dry_run)}.",
            "notice" if expected and not request.dry_run else "warning",
        )
    return ReuseOutcome(
        True,
        heading,
        "reused",
        f"Installed every guest image from {source}: its cache keys, the "
        "SHA-256 of each file, and their provenance check out.",
    )


def _escape_annotation(text: str, *, property_value: bool = False) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        text = text.replace(":", "%3A").replace(",", "%2C")
    return text


def report(outcome: ReuseOutcome, environment: Mapping[str, str]) -> None:
    """Print `outcome`, annotate a fallback to building, and give CI the
    `reused` step output and the job summary."""
    print(f">> {outcome.heading}: {outcome.status}. {outcome.detail}")
    if outcome.level is not None:
        title = _escape_annotation(outcome.heading, property_value=True)
        print(f"::{outcome.level} title={title}::{_escape_annotation(outcome.detail)}")
    output = environment.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"reused={'true' if outcome.reused else 'false'}\n")
    summary = environment.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(outcome.summary())


def reuse_in_ci(
    *,
    repository: str,
    workflow_ref: str,
    artifact: str,
    keys: str,
    commit: str | None,
    head_sha: str | None,
    dry_run: bool,
    destination: Path,
    environment: Mapping[str, str],
) -> ReuseOutcome:
    """Reuse the guest images with the token in GH_TOKEN or GITHUB_TOKEN,
    giving up on the artifact after REUSE_TIMEOUT_SECONDS, and report the
    outcome; every failure falls back to building."""
    token = environment.get("GH_TOKEN") or environment.get("GITHUB_TOKEN")
    deadline = time.monotonic() + REUSE_TIMEOUT_SECONDS
    try:
        if not token:
            raise ScriptError("no GitHub token is in GH_TOKEN or GITHUB_TOKEN")
        request = ReuseRequest(
            repository=repository,
            workflow_ref=workflow_ref,
            artifact=artifact,
            keys=parse_cache_keys(keys),
            commit=commit,
            head_sha=head_sha,
            dry_run=dry_run,
        )
    except ScriptError as error:
        outcome = ReuseOutcome(
            False,
            _REHEARSAL if dry_run else _REUSE,
            "build",
            f"{_sentence(str(error))}, so {_fallback(dry_run)}.",
            "warning",
        )
    else:
        outcome = reuse_guest_artifacts(
            RestApi(token, deadline), request, destination, deadline=deadline
        )
    report(outcome, environment)
    return outcome
