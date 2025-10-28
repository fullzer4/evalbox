//! Módulo de isolamento: namespaces, filesystem e security policies.
//!
//! Organiza os componentes de isolamento da sandbox.

pub mod namespaces;
pub mod filesystem;
pub mod security;

// Re-exports principais
pub use namespaces::{NamespaceConfig, create_namespaces};
pub use filesystem::{FilesystemConfig, setup_filesystem};
pub use security::{SecurityConfig, apply_security};
