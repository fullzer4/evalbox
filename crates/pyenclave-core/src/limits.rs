//! no_new_privs, rlimits (CPU/AS/NPROC/FSIZE), cgroups v2.
//!
//! Importante: `PR_SET_NO_NEW_PRIVS = 1` precisa ser aplicado **antes** de tentar
//! instalar o filtro seccomp (`SECCOMP_SET_MODE_FILTER`), caso contrário o kernel
//! retorna `EACCES`. Este módulo deve ser invocado na sequência anterior à
//! configuração do perfil seccomp.

use crate::spec::LimitSpec;
use nix::sys::resource::{setrlimit, Resource};

/// Configuração de limites de recursos
#[derive(Debug, Clone, Default)]
pub struct RLimitConfig {
    pub cpu_time_seconds: Option<u64>,
    pub memory_mb: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_file_size_mb: Option<u64>,
}

impl From<&LimitSpec> for RLimitConfig {
    fn from(spec: &LimitSpec) -> Self {
        Self {
            cpu_time_seconds: spec.time_limit_s,
            memory_mb: spec.memory_limit_mb,
            max_processes: spec.max_procs,
            max_file_size_mb: spec.fsize_mb,
        }
    }
}

pub fn apply_no_new_privs() -> Result<(), String> {
    // PR_SET_NO_NEW_PRIVS: impede que o processo ganhe privilégios
    // (necessário para aplicar seccomp sem CAP_SYS_ADMIN)
    unsafe {
        prctl::set_no_new_privileges(true)
            .map_err(|e| format!("Failed to set no_new_privs: {}", e))?;
    }
    
    Ok(())
}

pub fn apply_rlimits(config: &RLimitConfig) -> Result<(), String> {
    // Aplicar limite de CPU time (em segundos)
    if let Some(cpu_seconds) = config.cpu_time_seconds {
        setrlimit(Resource::RLIMIT_CPU, cpu_seconds, cpu_seconds)
            .map_err(|e| format!("Failed to set RLIMIT_CPU: {}", e))?;
    }
    
    // Aplicar limite de memória virtual (AS = Address Space)
    if let Some(memory_mb) = config.memory_mb {
        let bytes = memory_mb * 1024 * 1024;
        setrlimit(Resource::RLIMIT_AS, bytes, bytes)
            .map_err(|e| format!("Failed to set RLIMIT_AS: {}", e))?;
    }
    
    // Aplicar limite de número de processos
    if let Some(max_procs) = config.max_processes {
        setrlimit(Resource::RLIMIT_NPROC, max_procs, max_procs)
            .map_err(|e| format!("Failed to set RLIMIT_NPROC: {}", e))?;
    }
    
    // Aplicar limite de tamanho de arquivo
    if let Some(fsize_mb) = config.max_file_size_mb {
        let bytes = fsize_mb * 1024 * 1024;
        setrlimit(Resource::RLIMIT_FSIZE, bytes, bytes)
            .map_err(|e| format!("Failed to set RLIMIT_FSIZE: {}", e))?;
    }
    
    Ok(())
}

pub fn apply_rlimits_from_spec(lim: &LimitSpec) -> Result<(), String> {
    let config = RLimitConfig::from(lim);
    apply_rlimits(&config)
}

pub fn attach_cgroup_v2(_lim: &LimitSpec) -> Result<(), String> {
    // TODO: implementar cgroups v2 (opcional, mais avançado)
    // Requer escrever em /sys/fs/cgroup/*/memory.max, cpu.max, etc.
    Ok(())
}

/// Verifica se no_new_privs está ativo
pub fn is_no_new_privs_set() -> bool {
    use std::fs;
    
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        return status.lines()
            .any(|line| line.starts_with("NoNewPrivs:") && line.contains("1"));
    }
    
    false
}

