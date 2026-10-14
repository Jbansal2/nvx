"""Build and identify the Rust binaries installed in every Linux guest."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from .build_constants import BuildConstants, GuestRustBuildConstants
from .common import (
    ScriptError,
    normalized_sha256_file,
    require_file,
    require_tool,
    run_checked,
    sha256_file,
)
from .elf import check_static_executables


@dataclass(frozen=True)
class GuestBinaryBuildResult:
    """The source identity and executable identities of one guest build."""

    source_sha256: str
    binaries: dict[str, str]


def _build_manifest(result: GuestBinaryBuildResult) -> dict[str, object]:
    return {
        "format": GuestRustBuildConstants.BUILD_MANIFEST_FORMAT,
        "toolchain": GuestRustBuildConstants.TOOLCHAIN,
        "target": GuestRustBuildConstants.TARGET,
        "profile": GuestRustBuildConstants.PROFILE,
        "source_sha256": result.source_sha256,
        "binaries": result.binaries,
    }


def guest_binary_source_files(root: Path | None = None) -> tuple[Path, ...]:
    """Return the complete, ordered input set of the Rust guest binaries."""
    root = root or BuildConstants.REPO_ROOT
    crate = root / "nvx-rs"
    source_directory = crate / "src"
    if not source_directory.is_dir():
        raise ScriptError(f"nvx-rs source directory not found: {source_directory}")
    files = [
        crate / "Cargo.toml",
        crate / "Cargo.lock",
        crate / "build.rs",
        root / "rust-toolchain.toml",
        *(
            path
            for path in source_directory.rglob("*")
            if path.is_file()
            and "target" not in path.relative_to(source_directory).parts
        ),
    ]
    return tuple(
        sorted(
            (require_file(path, "Rust guest binary source input") for path in files),
            key=lambda path: path.relative_to(root).as_posix(),
        )
    )


def guest_binary_source_sha256(root: Path | None = None) -> str:
    """Hash the paths and contents that determine every Rust guest binary."""
    root = root or BuildConstants.REPO_ROOT
    inventory = {
        "domain": GuestRustBuildConstants.SOURCE_DIGEST_DOMAIN,
        "format": GuestRustBuildConstants.SOURCE_DIGEST_FORMAT,
        "files": [
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": normalized_sha256_file(path),
            }
            for path in guest_binary_source_files(root)
        ],
    }
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def pinned_guest_rust_toolchain(root: Path | None = None) -> str:
    """Read and validate the exact Rust release pinned by the repository."""
    toolchain_file = (root or BuildConstants.REPO_ROOT) / "rust-toolchain.toml"
    contents = require_file(toolchain_file, "Rust toolchain pin").read_text(
        encoding="utf-8"
    )
    matches = re.findall(r'^channel = "([^"]+)"$', contents, re.MULTILINE)
    if len(matches) != 1:
        raise ScriptError(f"{toolchain_file} must define one toolchain channel")
    [toolchain] = matches
    if toolchain != GuestRustBuildConstants.TOOLCHAIN:
        raise ScriptError(
            "Rust guest build toolchain mismatch: "
            f"build constants select {GuestRustBuildConstants.TOOLCHAIN}, "
            f"but rust-toolchain.toml selects {toolchain}"
        )
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain) is None:
        raise ScriptError(f"Rust guest build toolchain is not exact: {toolchain}")
    return toolchain


def _cargo_environment(target_directory: Path) -> dict[str, str]:
    environment = os.environ.copy()
    cargo_home = Path(
        environment.get("CARGO_HOME", str(Path.home() / ".cargo"))
    ).expanduser()
    if not cargo_home.is_absolute():
        cargo_home = (GuestRustBuildConstants.DIRECTORY / cargo_home).resolve()
    else:
        cargo_home = cargo_home.resolve()
    remap_flags = (
        f"--remap-path-prefix={BuildConstants.REPO_ROOT.resolve()}=/nvx-source",
        f"--remap-path-prefix={cargo_home}=/cargo-home",
        "-C",
        "link-arg=-Wl,--build-id=none",
    )
    environment.pop("RUSTFLAGS", None)
    environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(remap_flags)
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_TARGET_DIR"] = str(target_directory)
    environment["SOURCE_DATE_EPOCH"] = "0"
    return environment


def _guest_cargo_arguments() -> list[str]:
    return [
        "--locked",
        "--profile",
        GuestRustBuildConstants.PROFILE,
        "--target",
        GuestRustBuildConstants.TARGET,
        "--no-default-features",
        "--features",
        GuestRustBuildConstants.FEATURE,
    ]


def inspect_guest_binaries(directory: Path) -> GuestBinaryBuildResult:
    """Validate and identify a previously staged guest binary set."""
    paths = [directory / binary for binary in GuestRustBuildConstants.BINARIES]
    for binary, path in zip(GuestRustBuildConstants.BINARIES, paths, strict=True):
        require_file(path, f"prebuilt Rust guest binary {binary}")
    check_static_executables(paths)
    result = GuestBinaryBuildResult(
        source_sha256=guest_binary_source_sha256(),
        binaries={
            binary: sha256_file(path)
            for binary, path in zip(
                GuestRustBuildConstants.BINARIES, paths, strict=True
            )
        },
    )
    manifest_path = require_file(
        directory / GuestRustBuildConstants.BUILD_MANIFEST_NAME,
        "Rust guest binary build manifest",
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ScriptError(
            f"invalid Rust guest binary build manifest: {error}"
        ) from error
    expected = _build_manifest(result)
    if manifest != expected:
        raise ScriptError(
            "Rust guest binary build manifest does not match the current "
            "sources, build pins, and executables"
        )
    expected_names = {
        *GuestRustBuildConstants.BINARIES,
        GuestRustBuildConstants.BUILD_MANIFEST_NAME,
    }
    actual_names = {path.name for path in directory.iterdir()}
    if actual_names != expected_names:
        unexpected = sorted(actual_names - expected_names)
        missing = sorted(expected_names - actual_names)
        raise ScriptError(
            "Rust guest binary directory has an unexpected inventory: "
            f"extra={unexpected}, missing={missing}"
        )
    return result


def build_guest_binaries(output: Path) -> GuestBinaryBuildResult:
    """Build, check, and stage a fresh set of Rust guest executables."""
    if sys.platform != "linux":
        raise ScriptError("Rust guest binaries can be built only on Linux")
    if not output.name:
        raise ScriptError("guest binary output must name a directory")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    work = output.parent / f".{output.name}.work"
    target = work / "target"
    staging = work / "output"
    shutil.rmtree(work, ignore_errors=True)
    target.mkdir(parents=True)
    staging.mkdir()

    source_sha256 = guest_binary_source_sha256()
    toolchain = pinned_guest_rust_toolchain()
    cargo = require_tool("cargo")
    environment = _cargo_environment(target)
    cargo_arguments = _guest_cargo_arguments()
    try:
        hosted_command: list[str | os.PathLike[str]] = [
            cargo,
            f"+{toolchain}",
            "build",
            *cargo_arguments,
        ]
        for binary in GuestRustBuildConstants.HOSTED_BINARIES:
            hosted_command.extend(("--bin", binary))
        run_checked(
            hosted_command,
            cwd=GuestRustBuildConstants.DIRECTORY,
            env=environment,
        )
        for binary in GuestRustBuildConstants.FREESTANDING_BINARIES:
            run_checked(
                [
                    cargo,
                    f"+{toolchain}",
                    "rustc",
                    *cargo_arguments,
                    "--bin",
                    binary,
                    "--",
                    *GuestRustBuildConstants.FREESTANDING_RUSTFLAGS,
                ],
                cwd=GuestRustBuildConstants.DIRECTORY,
                env=environment,
            )

        built_directory = (
            target / GuestRustBuildConstants.TARGET / GuestRustBuildConstants.PROFILE
        )
        staged_paths: list[Path] = []
        for binary in GuestRustBuildConstants.BINARIES:
            source = require_file(
                built_directory / binary, f"built Rust guest binary {binary}"
            )
            destination = staging / binary
            shutil.copyfile(source, destination)
            destination.chmod(0o755)
            staged_paths.append(destination)
        check_static_executables(staged_paths)
        if guest_binary_source_sha256() != source_sha256:
            raise ScriptError(
                "Rust guest binary source inputs changed during the build"
            )
        result = GuestBinaryBuildResult(
            source_sha256=source_sha256,
            binaries={
                binary: sha256_file(staging / binary)
                for binary in GuestRustBuildConstants.BINARIES
            },
        )
        (staging / GuestRustBuildConstants.BUILD_MANIFEST_NAME).write_text(
            json.dumps(_build_manifest(result), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if output.exists():
            if not output.is_dir():
                raise ScriptError(
                    f"guest binary output exists and is not a directory: {output}"
                )
            shutil.rmtree(output)
        staging.replace(output)
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
