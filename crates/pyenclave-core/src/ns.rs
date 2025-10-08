//! Criação de namespaces (user, mount, pid, ipc, uts, net) e /proc (skeleton).
//!
//! Ao criar um namespace de PID, é obrigatório montar um `/proc` novo dentro do
//! enclave (após `pivot_root`) para que ferramentas funcionem corretamente.

pub struct NsHandles;

pub fn enter_namespaces() -> Result<NsHandles, String> {
    // TODO: unshare(CLONE_NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS|[NEWNET])
    // TODO: uid_map/gid_map com setgroups=deny
    Ok(NsHandles)
}

pub fn mount_proc() -> Result<(), String> {
    // TODO: montar /proc para o novo PID namespace
    Ok(())
}
