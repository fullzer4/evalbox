//! Ponte PyO3: expõe funções para Python e faz o *marshaling* dos tipos.
//!
//! Pipeline previsto (ordem "de aço") para `run`:
//! 1. `unshare` para user, mount, pid, ipc, uts e opcionalmente net namespaces.
//! 2. Propagar `uid_map`/`gid_map` com `setgroups` negado.
//! 3. Montar raiz `tmpfs`, aplicar binds RO/RW do `MountPlan` e executar `pivot_root`.
//! 4. Montar um `/proc` novo dentro do PID namespace.
//! 5. Aplicar `PR_SET_NO_NEW_PRIVS = 1` (pré-requisito para seccomp sem privilégios).
//! 6. Aplicar `rlimits` e/ou anexar cgroup v2 conforme `LimitSpec`.
//! 7. Materializar regras Landlock (filesystem apenas; rede fica a cargo do net
//!    namespace ou bloqueio de syscalls via seccomp).
//! 8. Carregar o filtro seccomp adequado (falha com `EACCES` se `no_new_privs` não
//!    estiver ativo).
//! 9. Configurar `PR_SET_PDEATHSIG` para matar a árvore se o supervisor encerrar.
//! 10. `execve` do Python alvo com `-I` e ambiente sanitizado (pycache prefix dentro
//!     do enclave, caches locais, etc.).

use pyo3::prelude::*;

mod spec;
mod preflight;
mod ns;
mod fs;
mod limits;
mod exec;
mod telemetry;
mod errors;
mod policy;

#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    /// Executa um job Python em enclave (skeleton).
    #[pyfn(m, "run")]
    fn py_run(_py: Python, _spec: &PyAny) -> PyResult<PyObject> {
        // TODO: converter _spec → spec::RunSpec e chamar runner interno.
        // Retornar um dict/obj com campos equivalentes ao ExecutionResult.
        Err(pyo3::exceptions::PyNotImplementedError::new_err("run: skeleton"))
    }

    /// Sonda capacidades do host (userns, seccomp, landlock, cgroups).
    #[pyfn(m, "py_probe")]
    fn py_probe(_py: Python) -> PyResult<PyObject> {
        // TODO: implementar preflight::probe_host()
        Err(pyo3::exceptions::PyNotImplementedError::new_err("probe: skeleton"))
    }

    /// Lista intérpretes detectados (se parte da descoberta for nativa).
    #[pyfn(m, "py_list_interpreters")]
    fn py_list_interpreters(_py: Python) -> PyResult<PyObject> {
        // TODO: opcional; pode ficar apenas no lado Python
        Err(pyo3::exceptions::PyNotImplementedError::new_err("list_interpreters: skeleton"))
    }

    Ok(())
}
