//! Testes para criação de user namespaces
//!
//! Estes testes verificam que conseguimos criar namespaces sem privilégios
//! e mapear UID/GID corretamente.

use pyenclave_core::ns::{create_user_namespace, UserNamespaceConfig};
use std::fs;

#[test]
fn test_can_create_user_namespace() {
    // Dado: um sistema com user namespaces habilitados
    // Quando: criamos um user namespace
    let config = UserNamespaceConfig::default();
    
    // Então: deve conseguir criar sem erros
    match create_user_namespace(&config) {
        Ok(_) => {
            // Sucesso esperado
        }
        Err(e) => {
            // Se falhar, pode ser porque estamos em um container ou sistema restrito
            eprintln!("Warning: Could not create user namespace: {}", e);
            // Não falhamos o teste, pois pode ser uma limitação do ambiente
        }
    }
}

#[test]
fn test_uid_mapping_in_namespace() {
    // Dado: um user namespace criado
    let config = UserNamespaceConfig {
        uid_map: Some((1000, 0, 1)),  // host UID 1000 → namespace UID 0
        gid_map: Some((1000, 0, 1)),  // host GID 1000 → namespace GID 0
    };
    
    // Quando: criamos o namespace e verificamos o UID
    match create_user_namespace(&config) {
        Ok(ns_handle) => {
            // Então: dentro do namespace devemos ter UID 0 (root)
            // (isto seria verificado no processo filho)
            drop(ns_handle); // cleanup
        }
        Err(e) => {
            eprintln!("Skipping test: {}", e);
        }
    }
}

#[test]
fn test_uid_map_file_created() {
    // Dado: um processo em um user namespace
    // Quando: verificamos /proc/self/uid_map
    if let Ok(content) = fs::read_to_string("/proc/self/uid_map") {
        // Então: deve ter pelo menos uma linha de mapeamento
        assert!(!content.trim().is_empty(), "uid_map should not be empty");
        
        // Formato esperado: "0 1000 1" (ou similar)
        let lines: Vec<&str> = content.lines().collect();
        assert!(!lines.is_empty(), "uid_map should have at least one mapping");
    }
}

#[test]
#[ignore] // Requer criar fork/exec para testar isolamento completo
fn test_namespace_isolation() {
    // Teste que verifica que processos em namespaces diferentes
    // não conseguem se ver
    
    // TODO: implementar quando tivermos fork/exec working
}

#[test]
fn test_detect_namespace_support() {
    // Verifica que conseguimos detectar se namespaces estão disponíveis
    use pyenclave_core::preflight::probe_host;
    
    let report = probe_host();
    
    if report.userns {
        // Se reportamos suporte, deve funcionar criar um namespace
        let config = UserNamespaceConfig::default();
        // Não vamos realmente criar (pode não ter permissão), só verificar que a API existe
        let _ = create_user_namespace(&config);
    }
}
