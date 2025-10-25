//! Apply Landlock: allowlist RO/RW according to MountPlan.
//!
//! Remember: Landlock only restricts filesystem operations. Network flows
//! must be handled via network namespace and/or seccomp rules.

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};
use std::path::Path;

/// Landlock access level for a path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockAccess {
    /// Read-only access (read files, list directories)
    ReadOnly,
    /// Read-write access (read, write, create, delete)
    ReadWrite,
}

/// A Landlock rule for a specific path
#[derive(Debug, Clone)]
pub struct LandlockRule {
    /// The filesystem path to apply the rule to
    pub path: String,
    /// The access level (read-only or read-write)
    pub access: LandlockAccess,
}

/// Detect the Landlock ABI version supported by the kernel
///
/// Returns None if Landlock is not supported (kernel < 5.13)
pub fn detect_landlock_abi() -> Option<u32> {
    // Try to create a minimal ruleset to test support
    // We'll try each ABI version starting from the highest
    for abi in [ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1] {
        let result = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create());
        
        if result.is_ok() {
            return Some(match abi {
                ABI::V5 => 5,
                ABI::V4 => 4,
                ABI::V3 => 3,
                ABI::V2 => 2,
                ABI::V1 => 1,
                ABI::Unsupported | _ => return None,
            });
        }
    }
    None
}

/// Apply Landlock filesystem access control rules
///
/// # Arguments
/// - `rules`: List of filesystem paths and their access levels
///
/// # Returns
/// - Ok(()) if Landlock was successfully applied
/// - Err(String) if Landlock is not supported or application failed
///
/// # Note
/// Landlock requires kernel >= 5.13. On older kernels, this will return an error.
pub fn apply_landlock_rules(rules: &[LandlockRule]) -> Result<(), String> {
    // Try to find a supported ABI, starting from the highest
    let mut abi_opt = None;
    for abi in [ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1] {
        let test_result = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(|r| r.create());
        
        if test_result.is_ok() {
            abi_opt = Some(abi);
            break;
        }
    }
    
    let abi = abi_opt.ok_or_else(|| {
        "Landlock not supported (kernel < 5.13 or not enabled)".to_string()
    })?;

    // Define the access rights we want to control
    let access_all = AccessFs::from_all(abi);

    // Create a Landlock ruleset
    let mut ruleset = Ruleset::default()
        .handle_access(access_all)
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?
        .create()
        .map_err(|e| format!("Failed to create Landlock ruleset: {}", e))?;

    // Add rules for each path
    for rule in rules {
        let path = Path::new(&rule.path);

        // Open the path to get a file descriptor
        let path_fd = PathFd::new(path)
            .map_err(|e| format!("Failed to open path '{}': {}", rule.path, e))?;

        // Determine the access rights based on the rule
        let access_rights = match rule.access {
            LandlockAccess::ReadOnly => {
                // Read-only: allow reading files and listing directories
                AccessFs::from_read(abi)
            }
            LandlockAccess::ReadWrite => {
                // Read-write: allow all filesystem operations
                AccessFs::from_all(abi)
            }
        };

        // Add the path rule to the ruleset
        ruleset = ruleset
            .add_rule(PathBeneath::new(path_fd, access_rights))
            .map_err(|e| format!("Failed to add rule for '{}': {}", rule.path, e))?;
    }

    // Restrict the calling thread to the ruleset
    ruleset
        .restrict_self()
        .map_err(|e| format!("Failed to restrict with Landlock: {}", e))?;

    Ok(())
}

/// Legacy function for backward compatibility (no arguments)
pub fn apply_landlock() -> Result<(), String> {
    // Empty ruleset - denies all filesystem access
    apply_landlock_rules(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_access_enum() {
        let ro = LandlockAccess::ReadOnly;
        let rw = LandlockAccess::ReadWrite;

        assert_eq!(ro, LandlockAccess::ReadOnly);
        assert_eq!(rw, LandlockAccess::ReadWrite);
        assert_ne!(ro, rw);
    }

    #[test]
    fn test_landlock_rule_construction() {
        let rule = LandlockRule {
            path: "/tmp".to_string(),
            access: LandlockAccess::ReadOnly,
        };

        assert_eq!(rule.path, "/tmp");
        assert_eq!(rule.access, LandlockAccess::ReadOnly);
    }
}

