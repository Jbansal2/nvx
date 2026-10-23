//! Tests of the checks of a one-shot run.

use std::fs;

use super::*;
use crate::host::python::fs::resolve;
use crate::host::sandbox::layer::LayerRole;

#[test]
fn run_checks_again_that_its_shares_do_not_overlap() {
    let directory = tempfile::tempdir().unwrap();
    let root = resolve(&PurePath::native(directory.path().to_str().unwrap())).unwrap();
    let path = |name: &str| root.join(name).as_str().to_owned();
    for (name, content) in [
        ("distro.erofs", "distro"),
        ("scratch.ext4", "scratch"),
        ("settings.json", "{}"),
        ("output.log", ""),
    ] {
        fs::write(path(name), content).unwrap();
    }
    let mounts = sandbox_mounts(
        &[
            format!("/etc/settings.json,{}", path("settings.json")),
            format!("/var/log/output.log,{},rw", path("output.log")),
        ],
        &[],
        None,
    )
    .unwrap();
    validate_mounts(&mounts).unwrap();
    let launch = SandboxLaunch::new(
        vec![SandboxLayer::new(
            LayerRole::Distro,
            &path("distro.erofs"),
            "11111111-1111-1111-1111-111111111111",
        )],
        &path("scratch.ext4"),
        SandboxSettings::default(),
    )
    .unwrap()
    .with_export(plan_mounts(&mounts).unwrap())
    .unwrap();
    let binding = validate_sandbox_systemd_policy(&launch).unwrap();
    run_plan(&launch, &binding).unwrap();

    // A hard link that replaced the read-only file with the writable one while the run verified
    // its distro layer would export one file under both access modes; the export plan's own
    // checks pass, since a file share's root is not pinned.
    fs::remove_file(path("settings.json")).unwrap();
    fs::hard_link(path("output.log"), path("settings.json")).unwrap();
    launch.export().unwrap().verify().unwrap();
    let error = run_plan(&launch, &binding).unwrap_err();
    assert_eq!(
        error.code(),
        Some(crate::ErrorCode::Unsupported),
        "{error:?}"
    );
    let message = error.message().unwrap_or_default();
    assert!(
        message.contains("name the same directory or file"),
        "{message}"
    );
}
