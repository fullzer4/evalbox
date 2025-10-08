//! Preparar ambiente e execve() do intérprete alvo (skeleton).

use crate::spec::RunSpec;

pub fn prepare_env(_spec: &RunSpec) -> Result<(), String> {
    // TODO: definir env seguro (PYTHONPYCACHEPREFIX para redirecionar .pyc ao
    // enclave, XDG_CACHE_HOME, controle de threads)
    Ok(())
}

pub fn set_pdeathsig() -> Result<(), String> {
    // TODO: prctl(PR_SET_PDEATHSIG, SIGKILL)
    Ok(())
}

pub fn exec_interpreter(_spec: &RunSpec) -> Result<(), String> {
    // TODO: execve() do Python alvo com -I e argv do spec
    Ok(())
}
