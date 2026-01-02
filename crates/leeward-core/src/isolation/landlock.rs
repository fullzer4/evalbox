//! Landlock filesystem sandboxing

use crate::Result;
use std::path::PathBuf;
use landlock::{
    Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI
};

/// Configuration for Landlock filesystem restrictions
#[derive(Debug, Clone, Default)]
pub struct LandlockConfig {
    /// Paths with read-only access
    pub ro_paths: Vec<PathBuf>,
    /// Paths with read-write access
    pub rw_paths: Vec<PathBuf>,
    /// Paths with execute permission
    pub exec_paths: Vec<PathBuf>,
}

impl LandlockConfig {
    /// Add a read-only path
    #[must_use]
    pub fn ro(mut self, path: impl Into<PathBuf>) -> Self {
        self.ro_paths.push(path.into());
        self
    }

    /// Add a read-write path
    #[must_use]
    pub fn rw(mut self, path: impl Into<PathBuf>) -> Self {
        self.rw_paths.push(path.into());
        self
    }

    /// Add an executable path
    #[must_use]
    pub fn exec(mut self, path: impl Into<PathBuf>) -> Self {
        self.exec_paths.push(path.into());
        self
    }

    /// Apply Landlock restrictions to the current process
    pub fn apply(&self) -> Result<()> {
        tracing::debug!(
            ro = self.ro_paths.len(),
            rw = self.rw_paths.len(),
            exec = self.exec_paths.len(),
            "applying landlock rules"
        );

        // Check if Landlock is supported - use V2 for now (Linux 5.19+)
        let abi = ABI::V2;
        tracing::debug!("Using Landlock ABI version: {:?}", abi);

        // Create ruleset with all filesystem access flags we want to control
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| crate::LeewardError::Landlock(format!("failed to create ruleset: {e}")))?
            .create()
            .map_err(|e| crate::LeewardError::Landlock(format!("failed to create ruleset: {e}")))?;

        // Add read-only paths
        let ro_access = AccessFs::ReadFile | AccessFs::ReadDir;
        for path in &self.ro_paths {
            if path.exists() {
                let file = std::fs::File::open(path)
                    .map_err(|e| crate::LeewardError::Landlock(format!("failed to open {}: {e}", path.display())))?;
                ruleset = ruleset
                    .add_rule(landlock::PathBeneath::new(file, ro_access))
                    .map_err(|e| crate::LeewardError::Landlock(format!(
                        "failed to add ro rule for {}: {e}",
                        path.display()
                    )))?;
                tracing::debug!("added read-only access for {}", path.display());
            }
        }

        // Add read-write paths
        let rw_access = AccessFs::ReadFile
            | AccessFs::WriteFile
            | AccessFs::ReadDir
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym;

        for path in &self.rw_paths {
            if path.exists() {
                let file = std::fs::File::open(path)
                    .map_err(|e| crate::LeewardError::Landlock(format!("failed to open {}: {e}", path.display())))?;
                ruleset = ruleset
                    .add_rule(landlock::PathBeneath::new(file, rw_access))
                    .map_err(|e| crate::LeewardError::Landlock(format!(
                        "failed to add rw rule for {}: {e}",
                        path.display()
                    )))?;
                tracing::debug!("added read-write access for {}", path.display());
            }
        }

        // Add execute paths
        let exec_access = AccessFs::Execute | AccessFs::ReadFile;
        for path in &self.exec_paths {
            if path.exists() {
                let file = std::fs::File::open(path)
                    .map_err(|e| crate::LeewardError::Landlock(format!("failed to open {}: {e}", path.display())))?;
                ruleset = ruleset
                    .add_rule(landlock::PathBeneath::new(file, exec_access))
                    .map_err(|e| crate::LeewardError::Landlock(format!(
                        "failed to add exec rule for {}: {e}",
                        path.display()
                    )))?;
                tracing::debug!("added execute access for {}", path.display());
            }
        }

        // Enforce the ruleset
        let status = ruleset
            .restrict_self()
            .map_err(|e| crate::LeewardError::Landlock(format!("failed to enforce landlock: {e}")))?;

        match status.ruleset {
            RulesetStatus::NotEnforced => {
                tracing::warn!("Landlock ruleset could not be enforced");
            }
            RulesetStatus::PartiallyEnforced => {
                tracing::info!("Landlock ruleset partially enforced");
            }
            RulesetStatus::FullyEnforced => {
                tracing::info!("Landlock ruleset fully enforced");
            }
        }

        Ok(())
    }
}
