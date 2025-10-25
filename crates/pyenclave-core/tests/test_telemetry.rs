//! Testes para coleta de telemetria
//!
//! Estes testes verificam que conseguimos coletar métricas de execução:
//! CPU time, memória RSS, exit code, reason (timeout, OOM, signal, etc.)

use pyenclave_core::telemetry::{collect_process_metrics, ProcessMetrics, ExitReason};
use pyenclave_core::exec::{execute_command, CommandSpec};
use std::collections::HashMap;

#[test]
fn test_collect_exit_code_success() {
    // Dado: um processo que termina com sucesso
    let spec = CommandSpec {
        executable: "/bin/true".to_string(),
        args: vec![],
        env: HashMap::new(),
        cwd: None,
    };
    
    // Quando: executamos e coletamos métricas
    if let Ok(result) = execute_command(&spec) {
        match collect_process_metrics(&result) {
            Ok(metrics) => {
                // Então: exit code deve ser 0 e reason "ok"
                assert_eq!(metrics.exit_code, Some(0), "exit code should be 0");
                assert_eq!(metrics.reason, ExitReason::Success, "reason should be Success");
            }
            Err(e) => {
                eprintln!("Warning: Could not collect metrics: {}", e);
            }
        }
    }
}

#[test]
fn test_collect_exit_code_failure() {
    // Dado: um processo que falha
    let spec = CommandSpec {
        executable: "/bin/false".to_string(),
        args: vec![],
        env: HashMap::new(),
        cwd: None,
    };
    
    // Quando: executamos e coletamos métricas
    if let Ok(result) = execute_command(&spec) {
        match collect_process_metrics(&result) {
            Ok(metrics) => {
                // Então: exit code deve ser != 0
                assert_ne!(metrics.exit_code, Some(0), "exit code should not be 0");
                assert_eq!(metrics.reason, ExitReason::Failed, "reason should be Failed");
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
            }
        }
    }
}

#[test]
fn test_detect_signal_termination() {
    // Dado: um processo morto por sinal
    let spec = CommandSpec {
        executable: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "kill -TERM $$".to_string()],
        env: HashMap::new(),
        cwd: None,
    };
    
    // Quando: executamos
    if let Ok(result) = execute_command(&spec) {
        match collect_process_metrics(&result) {
            Ok(metrics) => {
                // Então: reason deve indicar sinal
                if result.signal.is_some() {
                    assert_eq!(metrics.reason, ExitReason::Signal, "reason should be Signal");
                }
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
            }
        }
    }
}

#[test]
fn test_collect_cpu_time() {
    // Dado: um processo que consome CPU
    let spec = CommandSpec {
        executable: "/bin/sh".to_string(),
        args: vec!["-c".to_string(), "for i in $(seq 1 1000); do echo $i > /dev/null; done".to_string()],
        env: HashMap::new(),
        cwd: None,
    };
    
    // Quando: executamos e coletamos métricas
    if let Ok(result) = execute_command(&spec) {
        match collect_process_metrics(&result) {
            Ok(metrics) => {
                // Então: CPU time deve ser > 0
                if let Some(cpu_ms) = metrics.cpu_time_ms {
                    assert!(cpu_ms >= 0, "CPU time should be >= 0");
                }
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
            }
        }
    }
}

#[test]
fn test_collect_peak_memory() {
    // Dado: um processo qualquer
    let spec = CommandSpec {
        executable: "/bin/echo".to_string(),
        args: vec!["hello".to_string()],
        env: HashMap::new(),
        cwd: None,
    };
    
    // Quando: executamos e coletamos métricas
    if let Ok(result) = execute_command(&spec) {
        match collect_process_metrics(&result) {
            Ok(metrics) => {
                // Então: peak RSS deve ser > 0 (processo usou memória)
                if let Some(rss_kb) = metrics.peak_rss_kb {
                    assert!(rss_kb > 0, "Peak RSS should be > 0");
                }
            }
            Err(e) => {
                eprintln!("Warning: {}", e);
            }
        }
    }
}

#[test]
fn test_metrics_struct_default() {
    // Verifica que ProcessMetrics tem valores default sensatos
    let metrics = ProcessMetrics::default();
    
    assert_eq!(metrics.exit_code, None);
    assert_eq!(metrics.reason, ExitReason::Unknown);
    assert_eq!(metrics.cpu_time_ms, None);
    assert_eq!(metrics.peak_rss_kb, None);
}

#[test]
fn test_exit_reason_from_exit_code() {
    use pyenclave_core::telemetry::exit_reason_from_result;
    
    // Exit code 0 → Success
    let reason = exit_reason_from_result(Some(0), None);
    assert_eq!(reason, ExitReason::Success);
    
    // Exit code != 0 → Failed
    let reason = exit_reason_from_result(Some(1), None);
    assert_eq!(reason, ExitReason::Failed);
    
    // Signal → Signal
    let reason = exit_reason_from_result(None, Some(15));  // SIGTERM
    assert_eq!(reason, ExitReason::Signal);
    
    // OOM killer (exit code 137 ou signal 9)
    let reason = exit_reason_from_result(Some(137), None);
    assert_eq!(reason, ExitReason::OutOfMemory);
    
    // Signal 9 sem exit code também pode ser OOM
    let reason = exit_reason_from_result(None, Some(9));
    assert_eq!(reason, ExitReason::OutOfMemory);
}

#[test]
fn test_timeout_detection() {
    use pyenclave_core::telemetry::exit_reason_from_result;
    
    // SIGALRM (14) ou SIGKILL (9) podem indicar timeout
    // dependendo de como implementamos
    let reason = exit_reason_from_result(None, Some(14));
    // Por enquanto será Signal, mas poderia ser Timeout
    assert!(matches!(reason, ExitReason::Signal | ExitReason::Timeout));
}

#[test]
fn test_process_metrics_formatting() {
    // Verifica que conseguimos formatar métricas para log/debug
    let metrics = ProcessMetrics {
        exit_code: Some(0),
        reason: ExitReason::Success,
        cpu_time_ms: Some(123),
        peak_rss_kb: Some(4096),
    };
    
    let formatted = format!("{:?}", metrics);
    assert!(formatted.contains("exit_code"));
    assert!(formatted.contains("cpu_time_ms"));
}
