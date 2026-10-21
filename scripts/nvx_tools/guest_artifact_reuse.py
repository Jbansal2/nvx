"""The record of the guest images that a CI run built.

The build-guest-artifacts action records its cache keys and the SHA-256 of
each guest image file in the guest artifact record, which the artifacts job
uploads with the images, so that a later run can check that the images match
its own keys before it reuses them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .build_constants import DockerBuildConstants
from .common import (
    ScriptError,
    require_file,
    sha256_file,
    strict_json_object,
)

RECORD_NAME = "guest-artifacts.json"
RECORD_FORMAT = 1
# The files that the record describes. The action formats the Ubuntu sandbox
# scratch template in every run, so it is not one.
IMAGE_NAMES = DockerBuildConstants.ALL_GUEST_ARTIFACT_NAMES


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
    run's cache keys and the SHA-256 of each image file, which a later run
    checks before it reuses them."""
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
