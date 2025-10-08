//! no_new_privs, rlimits (CPU/AS/NPROC/FSIZE), cgroups v2 (opcional) (skeleton).
//!
//! Importante: `PR_SET_NO_NEW_PRIVS = 1` precisa ser aplicado **antes** de tentar
//! instalar o filtro seccomp (`SECCOMP_SET_MODE_FILTER`), caso contrário o kernel
//! retorna `EACCES`. Este módulo deve ser invocado na sequência anterior à
//! configuração do perfil seccomp.

use crate::spec::LimitSpec;

pub fn apply_no_new_privs() -> Result<(), String> {
    // TODO: prctl(PR_SET_NO_NEW_PRIVS, 1, ...)
    // Sem este passo, `policy::seccomp::apply_seccomp` falhará com EACCES.
    Ok(())
}

pub fn apply_rlimits(_lim: &LimitSpec) -> Result<(), String> {
    // TODO: setrlimit/prlimit conforme limites definidos
    Ok(())
}

pub fn attach_cgroup_v2(_lim: &LimitSpec) -> Result<(), String> {
    // TODO: opcional; escrever memory.max/cpu.max etc.
    Ok(())
}
