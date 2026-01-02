//! Unix socket server

use crate::{config::DaemonConfig, pool::WorkerPool};
use leeward_core::protocol::{self, Request, Response};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

/// Run the daemon server
pub async fn run(
    listener: UnixListener,
    pool: WorkerPool,
    _config: DaemonConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pool = Arc::new(pool);

    loop {
        let (stream, _) = listener.accept().await?;
        let pool = Arc::clone(&pool);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, pool).await {
                tracing::error!(error = %e, "connection error");
            }
        });
    }
}

/// Handle a single client connection
async fn handle_connection(
    mut stream: UnixStream,
    pool: Arc<WorkerPool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 64 * 1024]; // 64KB buffer

    loop {
        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // Client disconnected
        }
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > buf.len() {
            buf.resize(len, 0);
        }

        // Read message
        stream.read_exact(&mut buf[..len]).await?;

        // Decode request
        let request: Request = protocol::decode(&buf[..len])?;
        tracing::debug!(?request, "received request");

        // Handle request
        let response = handle_request(request, &pool).await;

        // Encode response
        let response_bytes = protocol::encode(&response)?;

        // Write length prefix + response
        let len_bytes = (response_bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}

/// Handle a single request
async fn handle_request(request: Request, pool: &WorkerPool) -> Response {
    match request {
        Request::Execute(req) => {
            // TODO: Handle shared memory mode (shm_slot_id)
            let code = match req.code {
                Some(ref code) => code,
                None => {
                    return Response::Execute(protocol::ExecuteResponse {
                        success: false,
                        result: None,
                        error: Some("no code provided (shared memory not yet implemented)".into()),
                    });
                }
            };

            match pool.execute(code).await {
                Ok(result) => Response::Execute(protocol::ExecuteResponse {
                    success: true,
                    result: Some(result),
                    error: None,
                }),
                Err(e) => Response::Execute(protocol::ExecuteResponse {
                    success: false,
                    result: None,
                    error: Some(e.to_string()),
                }),
            }
        }
        Request::Status => {
            let status = pool.status();
            Response::Status {
                total: status.total,
                idle: status.idle,
                busy: status.busy,
            }
        }
        Request::Ping => Response::Pong,
    }
}
