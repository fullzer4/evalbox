//! Plano de montagem: raiz tmpfs, binds RO/RW, pivot_root e /dev mínimo.

use crate::spec::MountPlan;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Configuração de bind mount
#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub readonly: bool,
}

/// Opções para criação da raiz isolada
#[derive(Debug, Clone, Default)]
pub struct MountOptions {
    pub size_mb: Option<u64>,
    pub tmpfs_options: Option<String>,
}

/// Caminhos reservados que não podem ser usados como mount targets
const RESERVED_PATHS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr",
];

pub fn create_isolated_root(options: &MountOptions) -> Result<(), String> {
    // 1. Criar diretório temporário para nova raiz
    let new_root = "/tmp/pyenclave_root";
    fs::create_dir_all(new_root)
        .map_err(|e| format!("Failed to create new root dir: {}", e))?;
    
    // 2. Montar tmpfs como nova raiz
    let tmpfs_opts = if let Some(size_mb) = options.size_mb {
        format!("size={}m,mode=0755", size_mb)
    } else {
        "size=256m,mode=0755".to_string()
    };
    
    mount(
        Some("tmpfs"),
        new_root,
        Some("tmpfs"),
        MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
        Some(tmpfs_opts.as_str()),
    )
    .map_err(|e| format!("Failed to mount tmpfs: {}", e))?;
    
    Ok(())
}

pub fn build_root(_plan: &MountPlan) -> Result<(), String> {
    // TODO: implementar montagem completa com binds RO/RW e pivot_root
    
    // 1. Criar tmpfs root
    create_isolated_root(&MountOptions::default())?;
    
    // 2. Criar estrutura de diretórios
    // 3. Aplicar binds RO/RW
    // 4. pivot_root
    
    Ok(())
}

pub fn mount_dev_minimal() -> Result<(), String> {
    setup_minimal_dev()
}

pub fn setup_minimal_dev() -> Result<(), String> {
    // Criar /dev se não existir
    let dev_path = Path::new("/dev");
    if !dev_path.exists() {
        fs::create_dir_all(dev_path)
            .map_err(|e| format!("Failed to create /dev: {}", e))?;
    }
    
    // Montar tmpfs em /dev
    mount(
        Some("tmpfs"),
        "/dev",
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("size=10m,mode=0755"),
    )
    .map_err(|e| format!("Failed to mount /dev tmpfs: {}", e))?;
    
    // Criar device nodes essenciais
    // TODO: mknod para /dev/null, /dev/zero, /dev/random, /dev/urandom
    // Por enquanto, apenas criar diretórios
    
    Ok(())
}

/// Valida que um caminho de mount é válido
pub fn validate_mount_path(path: &str) -> Result<(), String> {
    // Deve ser caminho absoluto
    if !path.starts_with('/') {
        return Err(format!("Mount path must be absolute: {}", path));
    }
    
    // Não pode ser um dos caminhos reservados
    for reserved in RESERVED_PATHS {
        if path == *reserved || path.starts_with(&format!("{}/", reserved)) {
            return Err(format!("Mount path is reserved: {}", path));
        }
    }
    
    Ok(())
}

/// Verifica se há colisões entre bind mounts
pub fn check_mount_collisions(binds: &[BindMount]) -> Result<(), String> {
    let mut targets = HashSet::new();
    
    for bind in binds {
        if !targets.insert(&bind.target) {
            return Err(format!("Mount collision detected: {}", bind.target));
        }
    }
    
    Ok(())
}

/// Aplica um bind mount
pub fn apply_bind_mount(bind: &BindMount) -> Result<(), String> {
    // Criar diretório de destino se não existir
    fs::create_dir_all(&bind.target)
        .map_err(|e| format!("Failed to create mount target {}: {}", bind.target, e))?;
    
    // Fazer bind mount
    mount(
        Some(bind.source.as_str()),
        bind.target.as_str(),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| format!("Failed to bind mount {} -> {}: {}", bind.source, bind.target, e))?;
    
    // Se for readonly, remontar como RO
    if bind.readonly {
        mount(
            Some(bind.source.as_str()),
            bind.target.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("Failed to remount {} as readonly: {}", bind.target, e))?;
    }
    
    Ok(())
}

/// Executa pivot_root para trocar a raiz do filesystem
pub fn do_pivot_root(new_root: &str, put_old: &str) -> Result<(), String> {
    use nix::unistd::pivot_root;
    
    // Criar diretório put_old dentro de new_root
    let put_old_path = format!("{}/{}", new_root, put_old);
    fs::create_dir_all(&put_old_path)
        .map_err(|e| format!("Failed to create put_old dir: {}", e))?;
    
    // Executar pivot_root (precisa de &str)
    pivot_root(new_root, put_old_path.as_str())
        .map_err(|e| format!("Failed to pivot_root: {}", e))?;
    
    // Mudar para a nova raiz
    std::env::set_current_dir("/")
        .map_err(|e| format!("Failed to chdir to new root: {}", e))?;
    
    // Desmontar a raiz antiga
    umount2(put_old, MntFlags::MNT_DETACH)
        .map_err(|e| format!("Failed to umount old root: {}", e))?;
    
    // Remover o diretório put_old
    fs::remove_dir(put_old)
        .map_err(|e| format!("Failed to remove put_old: {}", e))?;
    
    Ok(())
}

