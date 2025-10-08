//! Carregar filtro BPF para seccomp (deny rede/escape; allow mínimo p/ CPython) (skeleton).
//!
//! Pré-requisito: `limits::apply_no_new_privs` precisa ter executado com sucesso para
//! que o kernel aceite `SECCOMP_SET_MODE_FILTER` sem privilégios. Use este módulo
//! também para bloquear syscalls de rede quando o namespace de rede não estiver
//! isolado.

pub fn apply_seccomp(_profile_id: &str) -> Result<(), String> {
    // TODO: carregar BPF (por arquitetura) e instalar com seccomp()/prctl
    Ok(())
}
