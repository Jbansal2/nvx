//! Authorization inputs and opened-object observations for opt-in image-backed profiles.

use std::fs::File;
use std::path::{Path, PathBuf};

use super::{ExportPlan, ExportRequest, FileIdentity, PathList, canonicalize, check_root};
use crate::error::{Error, Result};
use crate::host::platform;

/// Kind of an authorized or opened host object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// Regular file, exposed without its parent directory.
    File,
    /// Directory root; changes within its declared subtree remain possible.
    Directory,
}

/// Access granted to an attachment or mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantAccess {
    /// Read-only.
    ReadOnly,
    /// Read-write, bounded by the export's writable-path policy when present.
    ReadWrite,
}

/// What the caller authorizes when a pathname is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSemantics {
    /// Follow this canonical name, while retaining kind, access, and protected-root constraints.
    LivePath,
    /// Use only the selected object. The VMM must retain/check its actual opened handle.
    ObjectPinned,
}

/// An observation made from an opened handle, not an expected identity label.
///
/// This type does not retain the handle. The VMM adapter must observe its actual attachment
/// handle and keep that handle pinned for the attachment's lifetime. Host inspection alone
/// and simulated receipts are not that VMM guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostObject {
    path: PathBuf,
    identity: FileIdentity,
    kind: ObjectKind,
    length: u64,
    ancestors: Vec<FileIdentity>,
}

impl HostObject {
    /// Observes `file` and verifies that `path` currently names the same opened object.
    ///
    /// The path and ancestry support protected-root checks; identity, kind and length come
    /// from the handle. A replacement during observation fails rather than joining two objects.
    pub fn from_opened(file: &File, path: &Path) -> Result<Self> {
        let path = canonicalize(path).map_err(|error| {
            Error::io(format!("cannot resolve opened object {}", path.display())).with_source(error)
        })?;
        check_root(&path)?;
        let metadata = file
            .metadata()
            .map_err(|error| Error::io("cannot inspect opened host object").with_source(error))?;
        let kind = if metadata.is_file() {
            ObjectKind::File
        } else if metadata.is_dir() {
            ObjectKind::Directory
        } else {
            return Err(Error::unsupported(
                "attachment must be a regular file or directory",
            ));
        };
        let (device, index) = platform::opened_file_identity(file)
            .map_err(|error| Error::io("cannot identify opened host object").with_source(error))?;
        let identity = FileIdentity { device, index };
        let ancestors = path
            .ancestors()
            .map(identity_at)
            .collect::<Result<Vec<_>>>()?;
        if ancestors.first() != Some(&identity) {
            return Err(Error::io(
                "the pathname changed while observing its opened object",
            ));
        }
        Ok(Self {
            path,
            identity,
            kind,
            length: metadata.len(),
            ancestors,
        })
    }

    /// Inspects a selected host object before authorization; not a VMM-open proof.
    pub fn inspect(path: &Path) -> Result<Self> {
        let file = platform::open_host_object(path).map_err(|error| {
            Error::io(format!("cannot open host object {}", path.display())).with_source(error)
        })?;
        Self::from_opened(&file, path)
    }

    /// Returns the canonical pathname.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the observed device/inode or volume/file index.
    pub fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Returns the kind observed from the handle.
    pub fn kind(&self) -> ObjectKind {
        self.kind
    }

    /// Returns the file length; no content hash is calculated.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Returns observed identities from this object through its canonical ancestors.
    pub fn ancestors(&self) -> &[FileIdentity] {
        &self.ancestors
    }
}

fn identity_at(path: &Path) -> Result<FileIdentity> {
    platform::file_identity(path)
        .map(|(device, index)| FileIdentity { device, index })
        .map_err(|error| {
            Error::io(format!("cannot identify {}", path.display())).with_source(error)
        })
}

/// A selected object and the exact access/path semantics the caller must approve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathGrant {
    object: HostObject,
    access: GrantAccess,
    semantics: PathSemantics,
}

impl PathGrant {
    /// Selects an existing object without making an authorization decision.
    pub fn inspect(path: &Path, access: GrantAccess, semantics: PathSemantics) -> Result<Self> {
        Ok(Self {
            object: HostObject::inspect(path)?,
            access,
            semantics,
        })
    }

    /// Returns the selected object.
    pub fn object(&self) -> &HostObject {
        &self.object
    }

    /// Returns the requested access.
    pub fn access(&self) -> GrantAccess {
        self.access
    }

    /// Returns the explicit replacement semantics.
    pub fn semantics(&self) -> PathSemantics {
        self.semantics
    }

    /// Rechecks at start/restore. This is deliberately not an opened VMM receipt.
    pub fn recheck(&self) -> Result<HostObject> {
        let current = HostObject::inspect(self.object.path())?;
        self.check_opened(&current, self.access)?;
        Ok(current)
    }

    /// Checks an adapter's actual opened observation against this authorization input.
    pub fn check_opened(&self, opened: &HostObject, access: GrantAccess) -> Result<()> {
        if opened.path != self.object.path
            || opened.kind != self.object.kind
            || access != self.access
            || (self.semantics == PathSemantics::ObjectPinned
                && opened.identity != self.object.identity)
        {
            return Err(Error::unsupported(format!(
                "opened object {} does not match its authorized kind, access, or path grant",
                opened.path.display()
            )));
        }
        Ok(())
    }
}

/// Mandatory caller-owned roots. None may be omitted or guessed by the core.
#[derive(Debug, Clone)]
pub struct ProtectedRootPaths {
    /// Runtime tools and bundles.
    pub runtime: PathBuf,
    /// Lifecycle records, capabilities, logs, and locks.
    pub state: PathBuf,
    /// Private caches.
    pub cache: PathBuf,
    /// Immutable image media.
    pub images: PathBuf,
    /// Reusable template media.
    pub templates: PathBuf,
}

/// Canonical, identity-pinned protected roots for one caller.
#[derive(Debug, Clone)]
pub struct ProtectedRoots {
    roots: [HostObject; 5],
}

impl ProtectedRoots {
    /// Resolves and pins all five roots; each must be an existing directory.
    pub fn new(paths: &ProtectedRootPaths) -> Result<Self> {
        let inspect = |path: &Path| {
            let object = HostObject::inspect(path)?;
            if object.kind != ObjectKind::Directory {
                return Err(Error::unsupported(
                    "every protected root must be a directory",
                ));
            }
            Ok(object)
        };
        Ok(Self {
            roots: [
                inspect(&paths.runtime)?,
                inspect(&paths.state)?,
                inspect(&paths.cache)?,
                inspect(&paths.images)?,
                inspect(&paths.templates)?,
            ],
        })
    }

    /// Refuses a changed protected root before a start/restore or receipt admission.
    pub fn recheck(&self) -> Result<()> {
        for root in &self.roots {
            let current = HostObject::inspect(root.path())?;
            if current.path != root.path
                || current.identity != root.identity
                || current.kind != root.kind
                || current.ancestors != root.ancestors
            {
                return Err(Error::unsupported("a protected root changed identity"));
            }
        }
        Ok(())
    }

    /// Returns all mandatory root observations for the versioned VMM handoff.
    pub fn objects(&self) -> &[HostObject; 5] {
        &self.roots
    }

    /// Requires internal runtime/media objects to lie below a caller-protected root.
    pub fn check_private(&self, object: &HostObject) -> Result<()> {
        if self.roots.iter().any(|root| {
            object.path.starts_with(&root.path) && object.ancestors.contains(&root.identity)
        }) {
            Ok(())
        } else {
            Err(Error::unsupported(
                "runtime, image, scratch, and template objects require a protected root",
            ))
        }
    }

    /// Rejects overlap in either direction, including aliases recognized by ancestor identities.
    ///
    /// Denying a child does not authorize exporting a parent of a protected root. Callers must
    /// additionally authorize every exposed object; this generic check is not that permission.
    pub fn check_export(&self, object: &HostObject) -> Result<()> {
        if self.roots.iter().any(|root| {
            object.path.starts_with(&root.path)
                || root.path.starts_with(&object.path)
                || object.ancestors.contains(&root.identity)
                || root.ancestors.contains(&object.identity)
        }) {
            return Err(Error::unsupported(format!(
                "host export {} overlaps a protected root",
                object.path.display()
            )));
        }
        Ok(())
    }
}

/// One explicit caller request to expose a host path.
#[derive(Debug, Clone)]
pub struct Exposure {
    /// Selected existing host path.
    pub path: PathBuf,
    /// Requested access.
    pub access: GrantAccess,
    /// Explicit live-name or pinned-object semantics.
    pub semantics: PathSemantics,
}

/// Authorized exports lowered by the existing planner, with separate VMM attachment grants.
#[derive(Debug, Clone)]
pub struct AuthorizedExports {
    plan: Option<ExportPlan>,
    children: Vec<PathGrant>,
    mappings: Vec<PathGrant>,
}

impl AuthorizedExports {
    /// Invokes the caller's authorization decision for every selected exposure, then reuses
    /// [`super::plan`]. Refuses policies whose read-only enforcement relies only on a guest bind.
    pub fn new(
        exposures: &[Exposure],
        denied: &[PathBuf],
        roots: &ProtectedRoots,
        mut authorize: impl FnMut(&PathGrant) -> Result<()>,
    ) -> Result<Self> {
        roots.recheck()?;
        let mut grants: Vec<PathGrant> = Vec::new();
        for exposure in exposures {
            let grant = PathGrant::inspect(&exposure.path, exposure.access, exposure.semantics)?;
            roots.check_export(grant.object())?;
            if let Some(previous) = grants
                .iter()
                .find(|previous| previous.object.path == grant.object.path)
                && (previous.access != grant.access || previous.semantics != grant.semantics)
            {
                return Err(Error::unsupported(
                    "one exposed path has conflicting grants",
                ));
            }
            authorize(&grant)?;
            grants.push(grant);
        }
        let paths = |access| {
            grants
                .iter()
                .filter(|grant| grant.access == access)
                .map(|grant| grant.object.path.clone())
                .collect::<Vec<_>>()
        };
        let read_only = paths(GrantAccess::ReadOnly);
        let read_write = paths(GrantAccess::ReadWrite);
        let mut plan = super::plan(&ExportRequest {
            read_only: PathList {
                name: "exports.readOnly",
                paths: &read_only,
            },
            read_write: PathList {
                name: "exports.readWrite",
                paths: &read_write,
            },
            denied: PathList {
                name: "exports.denied",
                paths: denied,
            },
        })?;
        let mut children = Vec::new();
        let mut mappings = Vec::new();
        if let Some(plan) = &mut plan {
            for child in &plan.children {
                let mut grant = grants
                    .iter()
                    .find(|grant| grant.object.path == child.root)
                    .cloned()
                    .ok_or_else(|| Error::other("export child lacks authorization"))?;
                grant.access = if child.writable {
                    GrantAccess::ReadWrite
                } else {
                    GrantAccess::ReadOnly
                };
                children.push(grant);
            }
            for bind in &mut plan.binds {
                let child = &plan.children[bind.child];
                let path = child.root.join(&bind.source);
                if bind.read_only
                    && child.writable
                    && (child.write.is_empty()
                        || child.write.iter().any(|write| path.starts_with(write)))
                {
                    return Err(Error::unsupported(
                        "a read-only mapping inside a writable mapping has no matching VMM enforcement",
                    ));
                }
                let grant = grants
                    .iter()
                    .find(|grant| grant.object.path == path)
                    .cloned()
                    .ok_or_else(|| Error::other("guest mapping lacks authorization"))?;
                bind.identity = (grant.semantics == PathSemantics::ObjectPinned)
                    .then_some(grant.object.identity);
                mappings.push(grant);
            }
        }
        let result = Self {
            plan,
            children,
            mappings,
        };
        result.recheck(roots)?;
        Ok(result)
    }

    /// Returns the unchanged, ordered aggregate/HostMap plan; this is not an attachment receipt.
    pub fn plan(&self) -> Option<&ExportPlan> {
        self.plan.as_ref()
    }

    /// Returns aggregate-child grants, in VMM child order.
    pub fn children(&self) -> &[PathGrant] {
        &self.children
    }

    /// Returns mapped-object grants in the guest's parent-before-child order.
    pub fn mappings(&self) -> &[PathGrant] {
        &self.mappings
    }

    /// Rechecks protected roots, selected grants and the original planner's movable denied paths.
    pub fn recheck(&self, roots: &ProtectedRoots) -> Result<()> {
        roots.recheck()?;
        if let Some(plan) = &self.plan {
            plan.verify()?;
        }
        for grant in self.children.iter().chain(&self.mappings) {
            roots.check_export(&grant.recheck()?)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_root_overlap_checks_identity_in_both_directions() {
        let directory = tempfile::tempdir().unwrap();
        let root_id = FileIdentity {
            device: 7,
            index: 11,
        };
        let alias_id = FileIdentity {
            device: 7,
            index: 12,
        };
        let root = HostObject {
            path: directory.path().join("private/root"),
            identity: root_id,
            kind: ObjectKind::Directory,
            length: 0,
            ancestors: vec![root_id, alias_id],
        };
        let protected = ProtectedRoots {
            roots: std::array::from_fn(|_| root.clone()),
        };
        let mut candidate = HostObject {
            path: directory.path().join("other/alias"),
            identity: FileIdentity {
                device: 8,
                index: 13,
            },
            kind: ObjectKind::Directory,
            length: 0,
            ancestors: Vec::new(),
        };
        protected.check_export(&candidate).unwrap();
        candidate.ancestors.push(root_id);
        assert!(protected.check_export(&candidate).is_err());
        candidate.ancestors.clear();
        candidate.identity = root_id;
        assert!(protected.check_export(&candidate).is_err());
        candidate.identity = alias_id;
        assert!(protected.check_export(&candidate).is_err());
    }
}
