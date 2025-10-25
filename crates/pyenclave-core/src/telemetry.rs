//! Coleta stdout/stderr, wait/status, rusage (CPU, pico RSS).

use crate::spec::RunResult;
use crate::exec::ExecutionResult;

/// Razão da terminação do processo
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    Success,        // Exit code 0
    Failed,         // Exit code != 0
    Signal,         // Morto por sinal
    Timeout,        // Timeout (SIGALRM ou SIGKILL por timer)
    OutOfMemory,    // OOM killer (exit 137 ou SIGKILL em situação de OOM)
    Unknown,        // Estado desconhecido
}

impl Default for ExitReason {
    fn default() -> Self {
        ExitReason::Unknown
    }
}

/// Métricas coletadas de um processo
#[derive(Debug, Clone, Default)]
pub struct ProcessMetrics {
    pub exit_code: Option<i32>,
    pub reason: ExitReason,
    pub cpu_time_ms: Option<u64>,
    pub peak_rss_kb: Option<u64>,
}

pub fn collect_output_and_wait() -> RunResult {
    // TODO: pipes p/ stdout/stderr, wait4, rusage
    // Por enquanto, retorna resultado vazio
    RunResult::default()
}

/// Determina a razão da terminação baseado em exit code e signal
pub fn exit_reason_from_result(exit_code: Option<i32>, signal: Option<i32>) -> ExitReason {
    // Se foi morto por sinal
    if let Some(sig) = signal {
        // SIGKILL (9) pode ser OOM ou timeout
        if sig == 9 {
            // Por enquanto, assumimos OOM (seria melhor verificar dmesg ou /proc)
            return ExitReason::OutOfMemory;
        }
        // SIGALRM (14) geralmente indica timeout
        if sig == 14 {
            return ExitReason::Timeout;
        }
        return ExitReason::Signal;
    }
    
    // Se tem exit code
    if let Some(code) = exit_code {
        // Exit 137 = 128 + 9 (SIGKILL) - geralmente OOM
        if code == 137 {
            return ExitReason::OutOfMemory;
        }
        // Exit 124 às vezes indica timeout (usado por timeout command)
        if code == 124 {
            return ExitReason::Timeout;
        }
        // Exit 0 = sucesso
        if code == 0 {
            return ExitReason::Success;
        }
        // Qualquer outro exit code != 0 = falha
        return ExitReason::Failed;
    }
    
    ExitReason::Unknown
}

/// Coleta métricas de um ExecutionResult
pub fn collect_process_metrics(result: &ExecutionResult) -> Result<ProcessMetrics, String> {
    let reason = exit_reason_from_result(result.exit_code, result.signal);
    
    // Por enquanto, não temos rusage no ExecutionResult
    // TODO: modificar execute_command para usar wait4 e coletar rusage
    
    Ok(ProcessMetrics {
        exit_code: result.exit_code,
        reason,
        cpu_time_ms: None,  // TODO: implementar com wait4
        peak_rss_kb: None,   // TODO: implementar com wait4
    })
}

/// Coleta métricas completas usando wait4 e rusage
/// Esta função seria chamada durante o wait do processo
pub fn collect_metrics_with_rusage(
    exit_code: Option<i32>,
    signal: Option<i32>,
) -> ProcessMetrics {
    let reason = exit_reason_from_result(exit_code, signal);
    
    // TODO: usar wait4 para obter rusage real
    // Por enquanto, retorna valores placeholder
    
    ProcessMetrics {
        exit_code,
        reason,
        cpu_time_ms: Some(0),   // TODO: rusage.ru_utime + ru_stime
        peak_rss_kb: Some(0),   // TODO: rusage.ru_maxrss
    }
}
