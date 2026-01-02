//! leeward CLI - Command line interface for the sandbox

use clap::{Parser, Subcommand};
use leeward_core::config::default_socket_path;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Send request to daemon and receive response
async fn send_request(
    socket_path: &PathBuf,
    request: &leeward_core::protocol::Request,
) -> Result<leeward_core::protocol::Response, Box<dyn std::error::Error>> {
    // Connect to daemon
    let mut stream = UnixStream::connect(socket_path).await?;

    // Encode request
    let request_bytes = leeward_core::protocol::encode(request)?;

    // Send length prefix (4 bytes, big-endian)
    let len = request_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;

    // Send request
    stream.write_all(&request_bytes).await?;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    // Read response
    let mut response_buf = vec![0u8; response_len];
    stream.read_exact(&mut response_buf).await?;

    // Decode response
    let response = leeward_core::protocol::decode(&response_buf)?;

    Ok(response)
}

#[derive(Parser)]
#[command(name = "leeward")]
#[command(author, version, about = "Linux-native sandbox for untrusted code execution")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute Python code
    Exec {
        /// Code to execute (or - for stdin)
        code: String,

        /// Socket path (defaults to LEEWARD_SOCKET env var or /run/leeward/leeward.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,

        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Memory limit in MB
        #[arg(short, long, default_value = "256")]
        memory: u64,
    },

    /// Get daemon status
    Status {
        /// Socket path (defaults to LEEWARD_SOCKET env var or /run/leeward/leeward.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },

    /// Ping the daemon
    Ping {
        /// Socket path (defaults to LEEWARD_SOCKET env var or /run/leeward/leeward.sock)
        #[arg(short, long)]
        socket: Option<PathBuf>,
    },

    /// Run code directly (without daemon, for testing)
    Run {
        /// Code to execute
        code: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,

        /// Memory limit in MB
        #[arg(short, long, default_value = "256")]
        memory: u64,

        /// Allow network access
        #[arg(long)]
        network: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("leeward=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Exec {
            code,
            socket,
            timeout,
            memory,
        } => {
            let socket = socket.unwrap_or_else(default_socket_path);

            let request = leeward_core::protocol::Request::Execute(
                leeward_core::protocol::ExecuteRequest {
                    code: Some(code),
                    shm_slot_id: None,
                    timeout: Some(std::time::Duration::from_secs(timeout)),
                    memory_limit: Some(memory * 1024 * 1024),
                    files: Vec::new(),
                }
            );

            match send_request(&socket, &request).await? {
                leeward_core::protocol::Response::Execute(resp) => {
                    if resp.success {
                        if let Some(result) = resp.result {
                            print!("{}", String::from_utf8_lossy(&result.stdout));
                            eprint!("{}", String::from_utf8_lossy(&result.stderr));
                            std::process::exit(result.exit_code);
                        }
                    } else {
                        eprintln!("Error: {}", resp.error.unwrap_or_else(|| "Unknown error".into()));
                        std::process::exit(1);
                    }
                }
                leeward_core::protocol::Response::Error { message } => {
                    eprintln!("Error: {}", message);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }

        Commands::Status { socket } => {
            let socket = socket.unwrap_or_else(default_socket_path);
            let request = leeward_core::protocol::Request::Status;

            match send_request(&socket, &request).await? {
                leeward_core::protocol::Response::Status { total, idle, busy } => {
                    println!("Workers: {} total, {} idle, {} busy", total, idle, busy);
                }
                leeward_core::protocol::Response::Error { message } => {
                    eprintln!("Error: {}", message);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }

        Commands::Ping { socket } => {
            let socket = socket.unwrap_or_else(default_socket_path);
            let request = leeward_core::protocol::Request::Ping;

            match send_request(&socket, &request).await? {
                leeward_core::protocol::Response::Pong => {
                    println!("Pong!");
                }
                leeward_core::protocol::Response::Error { message } => {
                    eprintln!("Error: {}", message);
                    std::process::exit(1);
                }
                _ => {
                    eprintln!("Unexpected response");
                    std::process::exit(1);
                }
            }
        }

        Commands::Run {
            code,
            timeout,
            memory,
            network,
        } => {
            println!("Running directly (no daemon)");
            println!("Code: {}", code);
            println!(
                "Timeout: {}s, Memory: {}MB, Network: {}",
                timeout, memory, network
            );

            // TODO: Use leeward_core directly to execute
            let _config = leeward_core::SandboxConfig::builder()
                .timeout_secs(timeout)
                .memory_limit_mb(memory)
                .allow_network(network)
                .build();
        }
    }

    Ok(())
}
