use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
};

use serde::{Deserialize, Serialize};

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::json;

const FOUNDRY_SOCKET_PATH: &str = "/var/run/foundry/foundry.socket";

/// Represents an incoming JSON-RPC request
#[derive(Serialize, Debug)]
struct Request {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

/// Represents an outgoing JSON-RPC response
#[derive(Deserialize, Debug)]
struct Response {
    jsonrpc: String,
    result: serde_json::Value,
    id: u64,
}

/// Represent an outgoing JSON-RPC error response
#[derive(Deserialize, Debug)]
struct ErrorResponse {
    jsonrpc: String,
    error: serde_json::Value,
    id: serde_json::Value,
}

/// CLI argument parser for foundry client commands
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available container lifecycle operations
#[derive(Parser, Debug)]
enum Commands {
    /// Create a container
    Create(CreateArgs),
    /// Start a container that has been created
    Start(LifecycleArgs),
    /// Stop a running container
    Kill(LifecycleArgs),
    /// Delete a stopped container
    Delete(LifecycleArgs),
}

/// Arguments for 'create' command: bundle path and container identifier
#[derive(Parser, Debug)]
struct CreateArgs {
    /// Path to the OCI bundle directory
    #[arg(required = true)]
    bundle_path: String,
    /// Unique ID
    container_id: String,
}

/// Arguments for lifecycle commands (start/kill/delete): container identifier only
#[derive(Parser, Debug)]
struct LifecycleArgs {
    /// The unique ID of the container
    #[arg(required = true)]
    container_id: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (method, params) = match cli.command {
        Commands::Create(args) => {
            println!("{args:?}");
            (
            "create",
            json!({
                "bundlePath": args.bundle_path,
                "containerId": args.container_id
            }),
        )},
        Commands::Start(args) => (
            "start",
            json!({
                "containerId": args.container_id
            }),
        ),
        Commands::Kill(args) => (
            "kill",
            json!({
                "containerId": args.container_id
            }),
        ),
        Commands::Delete(args) => (
            "delete",
            json!({
                "containerId": args.container_id
            }),
        ),
    };

    let mut stream = UnixStream::connect(FOUNDRY_SOCKET_PATH)
        .with_context(|| format!("Failed to connect to UNIX socket: {FOUNDRY_SOCKET_PATH}"))?;

    let request = Request {
        jsonrpc: "2.0".to_string(),
        method: method.to_string(),
        params,
        id: 1,
    };

    let request_json = serde_json::to_string(&request)? + "\n";
    stream
        .write_all(request_json.as_bytes())
        .with_context(|| "Failed to send JSON-RPC request to server")?;

    let mut response = String::new();
    let mut reader = BufReader::new(&stream);
    reader
        .read_line(&mut response)
        .with_context(|| "Failed to read JSON-RPC response.")?;

    let pretty_response =
        serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(&response)?)?;

    println!("{}", pretty_response);

    Ok(())
}
