//! Checks the launch profile and the option checks against `tests/fixtures/sandbox.json` and
//! `tests/fixtures/sandbox_options.json`, which the retired `scripts/nvx_rs_fixtures.py`
//! recorded from the Python launch profile and option checks of `nvx.py sandbox`, which nvx-rs
//! replaced.
//!
//! The fixtures hold the paths of both `pathlib` flavors, with a fixed current directory, so
//! every case runs on every host. The cases that read files run on files of a temporary
//! directory.
//!
//! Shares now reach OpenVMM and the guest through the export plan that the planner of every NVX
//! caller makes from resolved host paths, which [`mount::boot_shares`] renders, so no pure function
//! lowers a share anymore. To check that rendering against the records, each case stands in for
//! the plan with [`recorded_plan`]: one child for each share, in order, at the host path and with
//! the policy paths that the retired lowering gave OpenVMM. A launch plans its shares with
//! placeholder host paths, which neither its kernel command line nor its budget reads, and its
//! recorded arguments end with the rendering of the recorded plan.

use std::io;
use std::path::PathBuf;

use serde_json::{Value, json};

use super::mount::{
    POLICY_KINDS, aggregate_child_name, boot_shares, parse_mount_value, validate_mount_target,
    validate_mounts,
};
use super::options::{
    PolicyPathOption, SandboxOperation, SandboxOptions, sandbox_mounts_with,
    validate_exec_environment, validate_run_share_targets, validate_sandbox_systemd_policy,
};
use super::*;
use crate::host::filesystem::{Bind, ExportChild, Owner};
use crate::host::python::golden::{check_section, fixture, flavor, hex, text, texts};

/// Returns the message of a result's error, or `None` if it succeeded.
fn error<T>(result: &Result<T>) -> Option<String> {
    result.as_ref().err().map(ToString::to_string)
}

/// Returns `Path.cwd()` of the fixture for paths of `flavor`.
fn cwd(fixture: &Value, flavor: Flavor) -> impl Fn() -> io::Result<PurePath> {
    let name = match flavor {
        Flavor::Posix => "posix",
        Flavor::Windows => "windows",
    };
    let directory = PurePath::new(flavor, text(&fixture["cwds"], name));
    move || Ok(directory.clone())
}

/// Returns the fields of a share as the generator records them.
fn mount_fields(mount: &SandboxMount) -> Value {
    let policy = mount.policy();
    json!({
        "guest_target": mount.guest_target(),
        "host_path": mount.host_path().to_str().expect("a Unicode path"),
        "access": mount.access().as_str(),
        "denied": policy.denied,
        "allowed": policy.allowed,
        "writable": policy.writable,
        "owner": mount.owner().as_str(),
        "kind": mount.kind().as_str(),
    })
}

/// Parses the share of a generator's specification.
fn parse_mount(flavor: Flavor, spec: &Value) -> Result<SandboxMount> {
    let policy = MountPolicy {
        denied: texts(spec, "denied"),
        allowed: texts(spec, "allowed"),
        writable: texts(spec, "writable"),
    };
    SandboxMount::parse_in(
        flavor,
        text(spec, "value"),
        policy,
        MountOwner::from_name(text(spec, "owner"))?,
        MountKind::from_name(text(spec, "kind"))?,
    )
}

/// Returns the export plan whose rendering gives OpenVMM the arguments that the retired lowering
/// of `mounts` gave it: each share is a child of its own, in order, bound at its root, with its
/// host path as given and, unless `placeholders`, its policy paths, joined to the absolute host
/// path, as `cwd` makes it, in an aggregate, and as given for one directory.
///
/// With `placeholders`, the host paths are absolute paths of this host, and the plan has no
/// policy paths, so that a [`SandboxPlan`] takes it.
fn recorded_plan(
    mounts: &[SandboxMount],
    cwd: &dyn Fn() -> io::Result<PurePath>,
    placeholders: bool,
) -> Result<ExportPlan> {
    let aggregate = mounts.len() > 1 || mounts.iter().any(|mount| mount.kind() == MountKind::File);
    let mut children = Vec::with_capacity(mounts.len());
    let mut binds = Vec::with_capacity(mounts.len());
    for (index, mount) in mounts.iter().enumerate() {
        let policy: Vec<(PolicyKind, Vec<String>)> = if placeholders {
            Vec::new()
        } else if aggregate {
            mount.absolute_policy_paths_with(cwd)?
        } else {
            POLICY_KINDS
                .iter()
                .map(|&kind| (kind, mount.policy().paths(kind).to_vec()))
                .collect()
        };
        let paths = |wanted: PolicyKind| -> Vec<PathBuf> {
            policy
                .iter()
                .filter(|(kind, _)| *kind == wanted)
                .flat_map(|(_, paths)| paths.iter().map(PathBuf::from))
                .collect()
        };
        let denied = paths(PolicyKind::Denied);
        children.push(ExportChild {
            root: if placeholders {
                super::tests::host(&format!("/host{index}"))
            } else {
                mount.host_path().to_path_buf()
            },
            file: mount.kind() == MountKind::File,
            writable: mount.access() == MountAccess::ReadWrite,
            denied_identities: vec![None; denied.len()],
            denied,
            allowed: paths(PolicyKind::Allowed),
            write: paths(PolicyKind::Writable),
        });
        binds.push(Bind {
            child: index,
            source: String::new(),
            target: mount.guest_target().to_owned(),
            read_only: mount.access() == MountAccess::ReadOnly,
            identity: None,
        });
    }
    binds.sort_by(|left, right| {
        (left.target.matches('/').count(), &left.target)
            .cmp(&(right.target.matches('/').count(), &right.target))
    });
    Ok(ExportPlan {
        children,
        binds,
        owner: match mounts.first().map(SandboxMount::owner) {
            Some(MountOwner::Caller) => Owner::Caller,
            _ => Owner::Vmm,
        },
    })
}

/// Returns the expected outcome of a case: its `key` field, or its `error` field.
fn outcome(case: &Value, key: &str) -> std::result::Result<Value, String> {
    match case.get("error") {
        Some(Value::String(message)) => Err(message.clone()),
        _ => Ok(case[key].clone()),
    }
}

#[test]
fn identities_and_layers_parse_as_python_parses_them() {
    let fixture = fixture("sandbox.json");
    check_section(&fixture, "identities", |mismatches, case| {
        let actual = parse_workload_identity(text(case, "value"))
            .map(|(uid, gid)| json!([uid, gid]))
            .map_err(|error| error.to_string());
        mismatches.check(case, outcome(case, "identity"), actual);
    });

    check_section(&fixture, "layers", |mismatches, case| {
        let expected =
            outcome(case, "role").map(|_| json!([case["role"], case["path"], case["uuid"]]));
        let actual = SandboxLayer::parse_in(flavor(case), text(case, "value"))
            .map(|layer| {
                json!([
                    layer.role().as_str(),
                    layer.pure_path().as_str(),
                    layer.uuid()
                ])
            })
            .map_err(|error| error.to_string());
        mismatches.check(case, expected, actual);
    });
}

#[test]
fn mount_values_targets_and_child_names_match_python() {
    let fixture = fixture("sandbox.json");
    check_section(&fixture, "mount_values", |mismatches, case| {
        let expected = outcome(case, "target")
            .map(|_| json!([case["target"], case["host_path"], case["access"]]));
        let actual = parse_mount_value(text(case, "value"))
            .map(|(target, host_path, access)| json!([target, host_path, access.as_str()]))
            .map_err(|error| error.to_string());
        mismatches.check(case, expected, actual);
    });

    check_section(&fixture, "mount_targets", |mismatches, case| {
        mismatches.check(
            case,
            case["error"].as_str().map(str::to_owned),
            error(&validate_mount_target(text(case, "target"))),
        );
    });

    check_section(&fixture, "child_names", |mismatches, case| {
        let index = usize::try_from(case["index"].as_u64().unwrap()).unwrap();
        mismatches.check(
            case,
            text(case, "name"),
            aggregate_child_name(index, text(case, "target")).as_str(),
        );
    });
}

#[test]
fn mounts_lower_to_the_arguments_that_python_gives() {
    let fixture = fixture("sandbox.json");
    check_section(&fixture, "mounts", |mismatches, case| {
        let flavor = flavor(case);
        let cwd = cwd(&fixture, flavor);
        // The record gives every share the fragment of a directory share of its own, which a
        // file never used: OpenVMM appends the fragment of an aggregate for a file.
        let fragment = match case["mount"]["access"].as_str() {
            Some(access) if case["kind"] == "file" => json!(
                MountAccess::from_name(access)
                    .map(|access| mount::aggregate_command_line_fragment(&[access]))
                    .ok()
            ),
            _ => case["fragment"].clone(),
        };
        let expected = outcome(case, "mount").map(|_| {
            json!([
                case["mount"],
                case["arguments"],
                fragment,
                case["absolute"],
                case["absolute_policy"],
            ])
        });
        let actual = parse_mount(flavor, case).and_then(|mount| {
            let policy: Vec<Value> = mount
                .absolute_policy_paths_with(&cwd)?
                .into_iter()
                .map(|(kind, paths)| json!([kind.as_str(), paths]))
                .collect();
            let boot = boot_shares(&recorded_plan(std::slice::from_ref(&mount), &cwd, false)?)?;
            Ok(json!([
                mount_fields(&mount),
                boot.arguments,
                boot.fragment,
                mount_fields(&mount.absolute_with(&cwd)?),
                policy,
            ]))
        });
        mismatches.check(case, expected, actual.map_err(|error| error.to_string()));
    });
}

/// The records postdate the Python launch profile in two respects. They hold only launches of the
/// distro layer, the one layer that a sandbox takes. And the distro layer's token names the image
/// format, `erofs:`, before its UUID: the user command lines of the launches that fill the budget
/// exactly, or pass it by one byte, are six bytes shorter than recorded, the length of that
/// format, so that they keep their place at the boundary.
#[test]
fn launches_give_the_arguments_and_command_lines_that_python_gives() {
    let fixture = fixture("sandbox.json");
    check_section(&fixture, "launches", |mismatches, case| {
        let flavor = flavor(case);
        let layers = texts(case, "layers")
            .iter()
            .map(|value| {
                SandboxLayer::parse_in(flavor, value)
                    .expect("the generator records launches whose layers parse")
            })
            .collect();
        let mounts = case["mounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|spec| parse_mount(flavor, spec))
            .collect::<Result<Vec<_>>>()
            .expect("the generator records launches whose shares parse");
        let limit = |key: &str| case[key].as_str().map(|value| Int::parse(value).unwrap());
        let identity = &case["identity"];
        let id = |index: usize| u32::try_from(identity[index].as_u64().unwrap()).unwrap();
        let settings = SandboxSettings {
            entrypoint: text(case, "entrypoint").to_owned(),
            args: texts(case, "args"),
            hostname: text(case, "hostname").to_owned(),
            workload_identity: (id(0), id(1)),
            memory_max: limit("memory_max"),
            pids_max: limit("pids_max"),
        };
        let expected = match (case.get("error"), case.get("kernel_error")) {
            (Some(message), _) => Err(message.as_str().unwrap().to_owned()),
            (None, kernel_error) => Ok(json!([
                case["arguments"],
                case.get("kernel_command_line").unwrap_or(&Value::Null),
                kernel_error.unwrap_or(&Value::Null),
            ])),
        };
        let cwd = cwd(&fixture, flavor);
        let actual = SandboxLaunch::new_in(flavor, layers, text(case, "scratch"), settings)
            .and_then(|launch| {
                validate_mounts(&mounts)?;
                let export = if mounts.is_empty() {
                    None
                } else {
                    Some(recorded_plan(&mounts, &cwd, true)?)
                };
                let launch = launch.with_export(export)?;
                // `nvx.py` rendered the shares as boot tokens, as the one-shot lifecycle still
                // does.
                let mut arguments = launch.plan().one_shot_openvmm_arguments()?;
                if let Some(export) = launch.export() {
                    let placeholders = boot_shares(export)?.arguments.len();
                    arguments.truncate(arguments.len() - placeholders);
                    arguments.extend(boot_shares(&recorded_plan(&mounts, &cwd, false)?)?.arguments);
                }
                let command_line = launch
                    .plan()
                    .one_shot_kernel_command_line(text(case, "command_line"));
                Ok(json!([
                    arguments,
                    command_line.as_ref().ok(),
                    error(&command_line),
                ]))
            })
            .map_err(|error| error.to_string());
        mismatches.check(case, expected, actual);
    });
}

#[test]
fn sandbox_option_helpers_match_nvx_py() {
    let fixture = fixture("sandbox_options.json");
    check_section(&fixture, "run_share_targets", |mismatches, case| {
        let targets = texts(case, "targets");
        let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
        mismatches.check(
            case,
            case["error"].as_str().map(str::to_owned),
            error(&validate_run_share_targets(&targets)),
        );
    });

    check_section(&fixture, "sandbox_mounts", |mismatches, case| {
        let files = texts(case, "files");
        let policy_paths: Vec<PolicyPathOption> = case["policy"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| PolicyPathOption {
                kind: match option[0].as_str().unwrap() {
                    "denied" => PolicyKind::Denied,
                    "allowed" => PolicyKind::Allowed,
                    _ => PolicyKind::Writable,
                },
                preceding_mount: option[1]
                    .as_u64()
                    .map(|index| usize::try_from(index).unwrap()),
                path: option[2].as_str().unwrap().to_owned(),
            })
            .collect();
        let owner = case["owner"]
            .as_str()
            .map(|owner| MountOwner::from_name(owner).unwrap());
        let kind_of = |mount: &SandboxMount| {
            let host_path = mount.host_path().to_str().unwrap();
            if files.iter().any(|file| file == host_path) {
                MountKind::File
            } else {
                MountKind::Directory
            }
        };
        let actual = sandbox_mounts_with(
            flavor(case),
            &texts(case, "mounts"),
            &policy_paths,
            owner,
            &kind_of,
        )
        .map(|mounts| Value::Array(mounts.iter().map(mount_fields).collect()))
        .map_err(|error| error.to_string());
        mismatches.check(case, outcome(case, "result"), actual);
    });

    check_section(&fixture, "environments", |mismatches, case| {
        mismatches.check(
            case,
            case["error"].as_str().map(str::to_owned),
            error(&validate_exec_environment(&texts(case, "entries"))),
        );
    });
}

/// Returns the bytes of a document of the generator: its text, its bytes in hex, or a number
/// of spaces.
fn document(case: &Value) -> Vec<u8> {
    if let Some(text) = case["text"].as_str() {
        text.as_bytes().to_vec()
    } else if let Some(bytes) = case["bytes"].as_str() {
        hex(bytes)
    } else {
        let spaces = case["spaces"].as_u64().expect("a document");
        vec![b' '; usize::try_from(spaces).unwrap()]
    }
}

#[test]
fn environment_files_and_distro_manifests_read_as_python_reads_them() {
    let fixture = fixture("sandbox_options.json");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("environment.json");
    let path = path.to_str().unwrap();
    let shown = PurePath::native(path).as_str().to_owned();
    check_section(&fixture, "environment_files", |mismatches, case| {
        std::fs::write(path, document(case)).unwrap();
        let mut options = SandboxOptions::new(SandboxOperation::Exec);
        options.environment_file = Some(path.to_owned());
        let expected = match case.get("environment") {
            Some(environment) => Ok(environment.clone()),
            None => Err(text(case, "error").to_owned()),
        };
        let actual = options
            .check()
            .map(|environment| json!(environment))
            .map_err(|error| error.to_string().replace(&shown, "{path}"));
        mismatches.check(case, expected, actual);
    });

    let layer = directory.path().join("distro.erofs");
    std::fs::write(&layer, text(&fixture, "distro_layer")).unwrap();
    let manifest = directory.path().join("distro.erofs.manifest.json");
    let scratch = directory.path().join("scratch.ext4");
    let launch = SandboxLaunch::new(
        vec![SandboxLayer::new(
            LayerRole::Distro,
            layer.to_str().unwrap(),
            "11111111-1111-1111-1111-111111111111",
        )],
        scratch.to_str().unwrap(),
        SandboxSettings {
            entrypoint: "/sbin/init".to_owned(),
            ..SandboxSettings::default()
        },
    )
    .unwrap();
    check_section(&fixture, "distro_manifests", |mismatches, case| {
        std::fs::write(&manifest, document(&case["manifest"])).unwrap();
        mismatches.check(
            case,
            case["error"].as_str().map(str::to_owned),
            error(&validate_sandbox_systemd_policy(&launch)),
        );
    });
}
