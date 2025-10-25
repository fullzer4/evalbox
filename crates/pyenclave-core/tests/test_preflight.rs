//! Testes para detecção de capacidades do host (preflight)
//!
//! Estes testes verificam se conseguimos detectar as funcionalidades do kernel
//! necessárias para criar o sandbox (user namespaces, seccomp, landlock, etc.).

use pyenclave_core::preflight::{probe_host, HostReport};

#[test]
fn test_probe_host_returns_report() {
    // Dado: um sistema Linux
    // Quando: fazemos probe do host
    let report = probe_host();
    
    // Então: devemos receber um HostReport válido
    // (mesmo que algumas capacidades não estejam disponíveis)
    assert!(report.arch.is_some(), "arch should be detected");
    assert!(report.kernel.is_some(), "kernel version should be detected");
}

#[test]
fn test_detect_user_namespace_support() {
    // Dado: um sistema Linux moderno
    // Quando: verificamos suporte a user namespaces
    let report = probe_host();
    
    // Então: em sistemas modernos, user namespaces devem estar disponíveis
    // (skip se estiver em container sem permissões)
    if std::path::Path::new("/proc/sys/user/max_user_namespaces").exists() {
        let content = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .expect("should read max_user_namespaces");
        let max: i32 = content.trim().parse().unwrap_or(0);
        
        if max > 0 {
            assert!(report.userns, "user namespaces should be detected as available");
        }
    }
}

#[test]
fn test_detect_seccomp_support() {
    // Dado: um sistema Linux moderno
    // Quando: verificamos suporte a seccomp
    let report = probe_host();
    
    // Então: seccomp deve estar disponível em kernels 3.5+
    // Verificamos através de /proc/self/status
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if status.contains("Seccomp:") {
            assert!(report.seccomp, "seccomp should be detected");
        }
    }
}

#[test]
fn test_detect_landlock_abi() {
    // Dado: um sistema com kernel 5.13+
    // Quando: verificamos suporte a Landlock
    let report = probe_host();
    
    // Então: se Landlock estiver disponível, devemos ter um ABI version
    if report.landlock {
        assert!(report.landlock_abi.is_some(), "landlock ABI version should be set");
        assert!(report.landlock_abi.unwrap() >= 1, "landlock ABI should be at least v1");
    }
}

#[test]
fn test_detect_cgroups_v2() {
    // Dado: um sistema moderno
    // Quando: verificamos cgroups v2
    let report = probe_host();
    
    // Então: verificamos se /sys/fs/cgroup existe e é cgroups v2
    let cgroup_path = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers");
    if cgroup_path.exists() {
        assert!(report.cgroups_v2, "cgroups v2 should be detected");
    }
}

#[test]
fn test_arch_detection() {
    // Dado: qualquer arquitetura
    // Quando: detectamos a arquitetura
    let report = probe_host();
    
    // Então: deve corresponder à arquitetura de compilação
    let expected_arch = std::env::consts::ARCH;
    assert_eq!(
        report.arch.as_deref(),
        Some(expected_arch),
        "detected arch should match build arch"
    );
}

#[test]
fn test_kernel_version_format() {
    // Dado: um sistema Linux
    // Quando: detectamos a versão do kernel
    let report = probe_host();
    
    // Então: deve estar no formato X.Y.Z ou similar
    if let Some(kernel) = report.kernel {
        assert!(kernel.contains('.'), "kernel version should contain dots");
        // Ex: "6.6.52" ou "5.15.0-generic"
    }
}
