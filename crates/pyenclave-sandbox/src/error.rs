//! Sistema de erros da sandbox.
//!
//! Usa `thiserror` para erros de API pública (granulares) e permite
//! que implementações internas usem `anyhow::Result` para flexibilidade.

use thiserror::Error;

/// Erros públicos da API da sandbox.
#[derive(Error, Debug)]
pub enum Error {
    /// Falha em verificação de capacidades do host
    #[error("Preflight check failed: {0}")]
    Preflight(String),
    
    /// Falha na criação ou configuração de namespaces
    #[error("Namespace setup failed")]
    Namespace(#[source] anyhow::Error),
    
    /// Falha no isolamento de filesystem
    #[error("Filesystem isolation failed")]
    Filesystem(#[source] anyhow::Error),
    
    /// Falha na aplicação de políticas de segurança
    #[error("Security policy application failed")]
    Security(#[source] anyhow::Error),
    
    /// Falha na execução do processo
    #[error("Process execution failed")]
    Execution(#[source] anyhow::Error),
    
    /// Especificação inválida
    #[error("Invalid specification: {0}")]
    InvalidSpec(String),
    
    /// Erro de I/O genérico
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    
    /// Erro do nix (syscalls)
    #[error("System call error")]
    Nix(#[from] nix::Error),
}

/// Result type usando o Error da sandbox
pub type Result<T> = std::result::Result<T, Error>;

/// Converte anyhow::Error para Error::Execution (helper interno)
pub(crate) fn execution_error(err: anyhow::Error) -> Error {
    Error::Execution(err)
}

/// Converte anyhow::Error para Error::Namespace (helper interno)
pub(crate) fn namespace_error(err: anyhow::Error) -> Error {
    Error::Namespace(err)
}

/// Converte anyhow::Error para Error::Filesystem (helper interno)
pub(crate) fn filesystem_error(err: anyhow::Error) -> Error {
    Error::Filesystem(err)
}

/// Converte anyhow::Error para Error::Security (helper interno)
pub(crate) fn security_error(err: anyhow::Error) -> Error {
    Error::Security(err)
}
