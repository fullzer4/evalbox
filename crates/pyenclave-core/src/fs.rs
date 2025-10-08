//! Plano de montagem: raiz tmpfs, binds RO/RW, pivot_root e /dev mínimo (skeleton).

use crate::spec::MountPlan;

pub fn build_root(_plan: &MountPlan) -> Result<(), String> {
    // TODO: montar tmpfs como nova raiz; binds RO/RW; pivot_root; chdir("/")
    Ok(())
}

pub fn mount_dev_minimal() -> Result<(), String> {
    // TODO: expor /dev/null e o que mais for estritamente necessário (RO)
    Ok(())
}
