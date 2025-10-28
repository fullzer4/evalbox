//! Orquestrador do pipeline de execução.
//!
//! Gerencia a sequência correta de operações para executar código isolado.

use crate::{RunSpec, ExecutionResult, Error, Result};
use crate::error::{namespace_error, filesystem_error, security_error, execution_error};
use anyhow::Context;

/// Runtime para executar código em sandbox.
///
/// # Exemplo
///
/// ```no_run
/// use pyenclave_sandbox::{RunSpec, Runtime};
///
/// # fn main() -> Result<(), pyenclave_sandbox::Error> {
/// let spec = RunSpec::builder()
///     .interpreter("/usr/bin/python3".to_string())
///     .argv(vec!["-c".to_string(), "print('hello')".to_string()])
///     .build();
///
/// let runtime = Runtime::new(spec)?;
/// let result = runtime.execute()?;
/// # Ok(())
/// # }
/// ```
pub struct Runtime {
    spec: RunSpec,
}

impl Runtime {
    /// Cria novo runtime com a especificação fornecida.
    ///
    /// Valida a especificação antes de aceitar.
    pub fn new(spec: RunSpec) -> Result<Self> {
        spec.validate()
            .map_err(|e| Error::InvalidSpec(e))?;
        
        Ok(Self { spec })
    }
    
    /// Executa o pipeline completo de isolamento + execução.
    ///
    /// ## Pipeline de Execução
    ///
    /// 1. **Preflight checks**: Verifica capacidades do host
    /// 2. **Fork**: Separa processo pai (limpo) e filho (isolado)
    /// 3. **Setup (filho)**:
    ///    - Criar namespaces (user, mount, pid, ipc, uts, [net])
    ///    - Setup filesystem isolado (tmpfs, binds, pivot_root)
    ///    - Aplicar no_new_privs (ANTES de seccomp)
    ///    - Aplicar políticas de segurança (seccomp + Landlock)
    ///    - Aplicar limites de recursos (rlimits)
    ///    - Execve para o interpretador Python
    /// 4. **Wait (pai)**: Aguarda término e coleta métricas
    ///
    /// ## Erros
    ///
    /// Retorna erro se qualquer etapa do pipeline falhar.
    pub fn execute(self) -> Result<ExecutionResult> {
        // Preflight: verificar capacidades do host
        self.preflight()?;
        
        // TODO: Implementar fork + setup + wait
        // Por enquanto, retorna erro
        Err(Error::Execution(anyhow::anyhow!(
            "Runtime::execute not yet implemented - waiting for module implementations"
        )))
    }
    
    /// Verifica capacidades do host antes de executar
    fn preflight(&self) -> Result<()> {
        let report = crate::probe::probe_host();
        
        if !report.userns {
            return Err(Error::Preflight(
                "User namespaces not supported on this system".to_string()
            ));
        }
        
        if !report.seccomp {
            log::warn!("Seccomp not available - security will be reduced");
        }
        
        if !report.landlock {
            log::warn!("Landlock not available - filesystem isolation will be reduced");
        }
        
        Ok(())
    }
    
    /// Setup completo no processo filho (será chamado após fork)
    fn setup_child(&self) -> anyhow::Result<()> {
        // 1. Criar namespaces
        let ns_config = crate::isolation::NamespaceConfig::default();
        crate::isolation::create_namespaces(&ns_config)
            .context("Failed to create namespaces")?;
        
        // 2. Setup filesystem
        let fs_config = crate::isolation::FilesystemConfig::default();
        crate::isolation::setup_filesystem(&fs_config)
            .context("Failed to setup filesystem")?;
        
        // 3. no_new_privs (ANTES de seccomp - requisito do kernel)
        crate::execution::apply_no_new_privs()
            .context("Failed to apply no_new_privs")?;
        
        // 4. Aplicar políticas de segurança
        let security_config = crate::isolation::SecurityConfig::default();
        crate::isolation::apply_security(&security_config)
            .context("Failed to apply security policies")?;
        
        // 5. Aplicar limites
        let limit_config = crate::execution::LimitConfig::default();
        crate::execution::apply_limits(&limit_config)
            .context("Failed to apply resource limits")?;
        
        // 6. Execve será feito pelo caller
        Ok(())
    }
}
