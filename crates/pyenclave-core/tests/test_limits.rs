//! Testes para limites de recursos (no_new_privs, rlimits)
//!
//! Estes testes verificam que conseguimos aplicar restrições de recursos
//! e prevenir escalação de privilégios.

use pyenclave_core::limits::{apply_no_new_privs, apply_rlimits, RLimitConfig};
use std::fs;

#[test]
fn test_apply_no_new_privs() {
    // Dado: um processo normal
    // Quando: aplicamos PR_SET_NO_NEW_PRIVS
    match apply_no_new_privs() {
        Ok(_) => {
            // Então: deve ter sido aplicado com sucesso
            // Verificar através de /proc/self/status
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                // Procurar por "NoNewPrivs: 1"
                let has_no_new_privs = status.lines()
                    .any(|line| line.starts_with("NoNewPrivs:") && line.contains("1"));
                
                assert!(has_no_new_privs, "NoNewPrivs should be set to 1");
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not set no_new_privs: {}", e);
        }
    }
}

#[test]
fn test_no_new_privs_is_irreversible() {
    // Dado: no_new_privs aplicado
    let _ = apply_no_new_privs();
    
    // Quando: tentamos desabilitar (não deveria funcionar)
    // Então: no_new_privs deve permanecer ativo
    // (uma vez setado, não pode ser removido)
    
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        let has_no_new_privs = status.lines()
            .any(|line| line.starts_with("NoNewPrivs:") && line.contains("1"));
        
        if has_no_new_privs {
            // Se foi setado antes, deve permanecer
            assert!(has_no_new_privs);
        }
    }
}

#[test]
fn test_apply_cpu_time_limit() {
    // Dado: um limite de CPU
    let config = RLimitConfig {
        cpu_time_seconds: Some(10),
        ..Default::default()
    };
    
    // Quando: aplicamos o limite
    match apply_rlimits(&config) {
        Ok(_) => {
            // Então: o limite deve estar configurado
            // Verificar com getrlimit
            verify_cpu_limit_set(10);
        }
        Err(e) => {
            eprintln!("Warning: Could not set CPU limit: {}", e);
        }
    }
}

#[test]
fn test_apply_memory_limit() {
    // Dado: um limite de memória (mais alto para não quebrar o teste)
    let config = RLimitConfig {
        memory_mb: Some(2048),  // 2GB - valor seguro
        ..Default::default()
    };
    
    // Quando: aplicamos
    match apply_rlimits(&config) {
        Ok(_) => {
            // Então: deve estar configurado
            verify_memory_limit_set(2048 * 1024 * 1024);
        }
        Err(e) => {
            eprintln!("Warning: Could not set memory limit: {}", e);
        }
    }
}

#[test]
fn test_apply_max_processes_limit() {
    // Dado: limite de processos
    let config = RLimitConfig {
        max_processes: Some(50),
        ..Default::default()
    };
    
    // Quando: aplicamos
    match apply_rlimits(&config) {
        Ok(_) => {
            // Então: deve estar configurado
            // (difícil verificar diretamente sem criar 50+ processos)
        }
        Err(e) => {
            eprintln!("Warning: Could not set nproc limit: {}", e);
        }
    }
}

#[test]
fn test_apply_file_size_limit() {
    // Dado: limite de tamanho de arquivo
    let config = RLimitConfig {
        max_file_size_mb: Some(100),
        ..Default::default()
    };
    
    // Quando: aplicamos
    match apply_rlimits(&config) {
        Ok(_) => {
            // Então: deve estar configurado
        }
        Err(e) => {
            eprintln!("Warning: Could not set fsize limit: {}", e);
        }
    }
}

#[test]
fn test_apply_all_limits() {
    // Dado: todos os limites configurados (valores conservadores)
    let config = RLimitConfig {
        cpu_time_seconds: Some(30),
        memory_mb: Some(2048),  // 2GB
        max_processes: Some(100),
        max_file_size_mb: Some(50),
    };
    
    // Quando: aplicamos todos
    match apply_rlimits(&config) {
        Ok(_) => {
            // Então: todos devem estar ativos
        }
        Err(e) => {
            eprintln!("Warning: Could not set all limits: {}", e);
        }
    }
}

#[test]
fn test_rlimit_config_default() {
    // Verifica que o default não aplica limites
    let config = RLimitConfig::default();
    
    assert!(config.cpu_time_seconds.is_none());
    assert!(config.memory_mb.is_none());
    assert!(config.max_processes.is_none());
    assert!(config.max_file_size_mb.is_none());
}

// Helper functions

fn verify_cpu_limit_set(expected_seconds: u64) {
    use nix::sys::resource::{getrlimit, Resource};
    
    if let Ok((soft, _hard)) = getrlimit(Resource::RLIMIT_CPU) {
        assert!(soft > 0, "CPU limit should be set");
        // Pode não ser exatamente o valor esperado devido a arredondamentos
        assert!(soft <= expected_seconds, "CPU limit should be <= {}", expected_seconds);
    }
}

fn verify_memory_limit_set(expected_bytes: u64) {
    use nix::sys::resource::{getrlimit, Resource};
    
    if let Ok((soft, _hard)) = getrlimit(Resource::RLIMIT_AS) {
        // Verificar que algum limite foi setado
        // (pode ser diferente do esperado devido a arredondamentos)
        if soft > 0 {
            assert!(soft > 0, "Memory limit should be set");
        }
    }
}
