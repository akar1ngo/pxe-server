//! TFTP File Transfer Logic
//!
//! This module handles the actual file transfer operations for TFTP,
//! including reading files, handling retries, and managing transfer state.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::protocol::{
    BlockSizeConfig, TftpErrorCode, TftpOpcode, TransferMode, build_data, build_error, build_oack, get_tftp_opcode,
    parse_ack, parse_error,
};

const TIMEOUT_SECS: u64 = 3;
const MAX_RETRIES: usize = 8;

/// Transfer session configuration
#[derive(Debug, Clone)]
pub struct TransferConfig {
    pub root_dir: PathBuf,
    pub block_size: BlockSizeConfig,
    pub timeout: Duration,
    pub max_retries: usize,
    pub local_bind: Option<IpAddr>,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("./tftp_root"),
            block_size: BlockSizeConfig::default(),
            timeout: Duration::from_secs(TIMEOUT_SECS),
            max_retries: MAX_RETRIES,
            local_bind: None,
        }
    }
}

/// Handle a TFTP Read Request
pub async fn handle_read_request(
    client: SocketAddr,
    filename: String,
    mode: String,
    options: &HashMap<String, String>,
    config: &TransferConfig,
) -> Result<()> {
    // Parse and validate transfer mode
    let transfer_mode: TransferMode = mode
        .parse()
        .map_err(|e| anyhow::anyhow!("Unsupported transfer mode: {}", e))?;

    if !transfer_mode.is_supported() {
        let sock = create_ephemeral_socket(client, config.local_bind).await?;
        let error_msg = format!("Transfer mode '{}' not supported", mode);
        sock.send_to(
            &build_error(TftpErrorCode::IllegalOperation.as_u16(), &error_msg),
            client,
        )
        .await?;
        return Ok(());
    }

    // Resolve and validate file path
    let file_path = validate_file_path(&config.root_dir, &filename)?;

    // Check if file exists
    if !file_path.exists() {
        let sock = create_ephemeral_socket(client, config.local_bind).await?;
        sock.send_to(
            &build_error(TftpErrorCode::FileNotFound.as_u16(), "File not found"),
            client,
        )
        .await?;
        return Ok(());
    }

    // Read file into memory
    // TODO: For large files, consider streaming reads
    let file_data = std::fs::read(&file_path).context("read file")?;
    let file_size = file_data.len();

    // Determine block size from options
    let block_size_config = BlockSizeConfig::from_options(options);
    let mut negotiated_block_size = block_size_config.size;
    let mut accepted_options = HashMap::new();

    if options.contains_key("tsize") {
        accepted_options.insert("tsize".to_string(), file_size.to_string());
    }

    if let Some(req_str) = options.get("blksize") {
        if let Ok(req_val) = req_str.parse::<usize>() {
            let negotiated = std::cmp::min(req_val, BlockSizeConfig::MAX);
            negotiated_block_size = negotiated;
            accepted_options.insert("blksize".to_string(), negotiated.to_string());
        } else {
            // Malformed blksize requested; ignore and use default.
        }
    }

    if options.get("windowsize").is_some() {
        // We do not support windowed transfers, so we will echo back the option set to 1.
        accepted_options.insert("windowsize".to_string(), "1".to_string());
    }

    // If client requests timeout, echo the same timeout back. TianoCore considers an OACK
    // malformed if we do not provide the exact set of options back.
    if let Some(timeout_str) = options.get("timeout") {
        accepted_options.insert("timeout".to_string(), timeout_str.to_owned());
    }

    // Create ephemeral socket for this transfer
    let sock = create_ephemeral_socket(client, config.local_bind).await?;

    // Send OACK if options were negotiated
    if !accepted_options.is_empty() {
        send_oack_and_wait_ack(&sock, client, &accepted_options, config).await?;
    }

    // Send file data
    send_file_data(&sock, client, &file_data, negotiated_block_size, config).await?;

    tracing::info!("Successfully transferred {} to {}", filename, client);
    Ok(())
}

/// Validate file path and check for path traversal attacks
fn validate_file_path(root: impl AsRef<Path>, filename: &str) -> Result<PathBuf> {
    let requested = root.as_ref().join(filename);

    // Canonicalize paths to detect traversal attempts
    let root_canon = root
        .as_ref()
        .canonicalize()
        .context("failed to canonicalize root directory")?;
    let path_canon = requested
        .canonicalize()
        .context("failed to canonicalize requested path")?;

    // Ensure the requested file is within the root directory
    if !path_canon.starts_with(&root_canon) {
        return Err(anyhow!("Path traversal attempt detected"));
    }

    Ok(path_canon)
}

/// Create an ephemeral UDP socket appropriate for the client address family
async fn create_ephemeral_socket(client: SocketAddr, local_bind: Option<IpAddr>) -> Result<UdpSocket> {
    let bind_addr = if let Some(ip) = local_bind {
        match ip {
            IpAddr::V4(v4) => format!("{}:0", v4),
            IpAddr::V6(v6) => format!("[{}]:0", v6),
        }
    } else {
        match client {
            SocketAddr::V4(_) => "0.0.0.0:0".to_string(),
            SocketAddr::V6(_) => "[::]:0".to_string(),
        }
    };

    let sock = UdpSocket::bind(&bind_addr)
        .await
        .context("failed to bind ephemeral socket")?;

    tracing::debug!("Transfer socket bound to {}", sock.local_addr()?);
    Ok(sock)
}

/// Send OACK and wait for ACK(0)
async fn send_oack_and_wait_ack(
    sock: &UdpSocket,
    client: SocketAddr,
    options: &HashMap<String, String>,
    config: &TransferConfig,
) -> Result<()> {
    let oack_packet = build_oack(options);
    tracing::debug!(
        "Sending OACK to {}: opts={:?}, bytes={:?}",
        client,
        options,
        oack_packet
    );

    for attempt in 0..config.max_retries {
        sock.send_to(&oack_packet, client).await?;

        match timeout(config.timeout, recv_from_client(sock, client)).await {
            Ok(Ok(packet)) => {
                if let Some(opcode) = get_tftp_opcode(&packet) {
                    match opcode {
                        TftpOpcode::Acknowledgment => {
                            if let Ok(ack_block) = parse_ack(&packet)
                                && ack_block == 0
                            {
                                return Ok(()); // Proceed with data transfer
                            }
                        }
                        TftpOpcode::Error => {
                            if let Ok((code, msg)) = parse_error(&packet) {
                                return Err(anyhow!("Client error during OACK: {} - {}", code, msg));
                            }
                            return Err(anyhow!("Client error during OACK"));
                        }
                        _ => {
                            // Unexpected packet, ignore and retry
                        }
                    }
                }
            }
            _ => {
                if attempt + 1 == config.max_retries {
                    return Err(anyhow!("No ACK(0) received after OACK; transfer aborted"));
                }
                // Retry
            }
        }
    }

    Err(anyhow!("Failed to receive ACK after OACK"))
}

/// Send file data in blocks
async fn send_file_data(
    sock: &UdpSocket,
    client: SocketAddr,
    data: &[u8],
    block_size: usize,
    config: &TransferConfig,
) -> Result<()> {
    let file_size = data.len();

    // Handle empty file case
    if file_size == 0 {
        let zero_packet = build_data(1, &[]);
        send_data_block_with_retries(sock, client, &zero_packet, 1, config).await?;
        return Ok(());
    }

    // Send data blocks
    let mut offset = 0;
    let mut block_num: u16 = 1;

    while offset < file_size {
        let end = std::cmp::min(offset + block_size, file_size);
        let chunk = &data[offset..end];
        let packet = build_data(block_num, chunk);

        send_data_block_with_retries(sock, client, &packet, block_num, config).await?;

        offset = end;

        // If we sent a short block, transfer is complete
        if chunk.len() < block_size {
            return Ok(());
        }

        block_num = block_num.wrapping_add(1);
    }

    // If file size is an exact multiple of block size, send final empty block
    if file_size.is_multiple_of(block_size) {
        let final_packet = build_data(block_num, &[]);
        send_data_block_with_retries(sock, client, &final_packet, block_num, config).await?;
    }

    Ok(())
}

/// Send a data block with retries and wait for ACK
async fn send_data_block_with_retries(
    sock: &UdpSocket,
    client: SocketAddr,
    packet: &[u8],
    expected_ack: u16,
    config: &TransferConfig,
) -> Result<()> {
    for attempt in 0..config.max_retries {
        sock.send_to(packet, client).await?;

        match timeout(config.timeout, recv_from_client(sock, client)).await {
            Ok(Ok(response)) => {
                if let Some(opcode) = get_tftp_opcode(&response) {
                    match opcode {
                        TftpOpcode::Acknowledgment => {
                            if let Ok(ack_block) = parse_ack(&response)
                                && ack_block == expected_ack
                            {
                                return Ok(());
                            }
                        }
                        TftpOpcode::Error => {
                            if let Ok((code, msg)) = parse_error(&response) {
                                return Err(anyhow!("Client error: {} - {}", code, msg));
                            }
                            return Err(anyhow!("Client returned error"));
                        }
                        _ => {
                            // Unexpected packet type, ignore
                        }
                    }
                }
            }
            _ => {
                if attempt + 1 == config.max_retries {
                    return Err(anyhow!("No ACK received for block {}", expected_ack));
                }
                // Timeout, retry
            }
        }
    }

    Err(anyhow!("Failed to send block {} after retries", expected_ack))
}

/// Receive a packet from a specific client, ignoring packets from other sources
async fn recv_from_client(sock: &UdpSocket, client: SocketAddr) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 1500]; // MTU size buffer

    loop {
        let (n, src) = sock.recv_from(&mut buf).await?;

        if src == client {
            buf.truncate(n);
            return Ok(buf);
        }

        // Ignore packets from other sources
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_validate_file_path() {
        let temp_dir = tempdir().unwrap();
        let root = temp_dir.path().to_path_buf();

        // Create a test file
        let test_file = root.join("test.txt");
        std::fs::write(&test_file, b"test content").unwrap();

        // Valid path should work
        let result = validate_file_path(&root, "test.txt");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_file.canonicalize().unwrap());

        // Path traversal should be rejected
        let result = validate_file_path(&root, "../../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_config_default() {
        let config = TransferConfig::default();
        assert_eq!(config.block_size.size, BlockSizeConfig::DEFAULT);
        assert_eq!(config.timeout, Duration::from_secs(TIMEOUT_SECS));
        assert_eq!(config.max_retries, MAX_RETRIES);
        assert_eq!(config.root_dir, PathBuf::from("./tftp_root"));
    }
}
