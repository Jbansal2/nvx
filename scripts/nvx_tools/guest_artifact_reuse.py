"""The record of the guest artifact components that a CI run built.

The build-guest-artifacts action records the exact cache keys and the SHA-256
of each file of its components in a guest artifact record, which it uploads
beside the components' own artifacts, so that a later run can check that the
components match its own keys before it reuses them.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

from .common import (
    ScriptError,
    require_file,
    sha256_file,
    strict_json_object,
)
from .release import GUEST_ARTIFACT_COMPONENTS

RECORD_NAME = "guest-artifacts.json"
RECORD_FORMAT = 1
# The outputs of the action's key step that key the cache entries of each
# component that a record covers: those that a package ships.
COMPONENT_CACHE_KEYS: Mapping[str, tuple[str, ...]] = {
    "kernel": ("kernel",),
    "alpine": ("alpine",),
    "ubuntu": ("ubuntu", "ubuntu-distro"),
    "azurelinux": ("azurelinux",),
}


def parse_components(text: str) -> tuple[str, ...]:
    """Parse the space-separated guest artifact components of a record, as
    the action's components input lists them."""
    names = set(text.split())
    unknown = sorted(names - COMPONENT_CACHE_KEYS.keys())
    if unknown:
        raise ScriptError(
            f"no guest artifact record covers {', '.join(unknown)}, only "
            f"{', '.join(COMPONENT_CACHE_KEYS)}"
        )
    if not names:
        raise ScriptError("no guest artifact component is selected")
    return tuple(name for name in COMPONENT_CACHE_KEYS if name in names)


def component_files(components: Sequence[str]) -> tuple[str, ...]:
    """Return the names of the files of `components` in build/."""
    return tuple(
        name
        for component in components
        for name in GUEST_ARTIFACT_COMPONENTS[component]
    )


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


def component_keys(
    components: Sequence[str],
    keys: Mapping[str, str],
) -> dict[str, str]:
    """Return, by name, the exact cache keys among `keys` of the cache entries
    of `components`."""
    selected: dict[str, str] = {}
    for component in components:
        for name in COMPONENT_CACHE_KEYS[component]:
            if not keys.get(name):
                raise ScriptError(f"the cache keys give no {name} key")
            selected[name] = keys[name]
    return dict(sorted(selected.items()))


def record_guest_artifacts(
    directory: Path,
    components: Sequence[str],
    keys: Mapping[str, str],
) -> Path:
    """Write the guest artifact record of `components` in `directory`: the
    exact cache keys of their cache entries, from `keys`, and the SHA-256 of
    each of their files, which a later run checks before it reuses them."""
    files = {
        name: sha256_file(require_file(directory / name, f"guest artifact {name}"))
        for name in component_files(components)
    }
    document = {
        "format": RECORD_FORMAT,
        "keys": component_keys(components, _cache_keys(dict(keys))),
        "files": files,
    }
    path = directory / RECORD_NAME
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path
