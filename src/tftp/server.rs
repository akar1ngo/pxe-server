//! TFTP Server Implementation
//!
//! This module contains the main TFTP server logic that handles incoming
//! requests and dispatches them to appropriate handlers.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;

use crate::tftp::protocol::{TftpOpcode, get_tftp_opcode, parse_rrq};
use crate::tftp::transfer::{TransferConfig, handle_read_request};

/// TFTP Server configuration
#[derive(Debug, Clone)]
pub struct TftpServerConfig {
    pub bind_address: String,
    pub root_directory: PathBuf,
    pub transfer_config: TransferConfig,
}

impl Default for TftpServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:6969".to_string(),
            root_directory: PathBuf::from("./tftp_root"),
            transfer_config: TransferConfig::default(),
        }
    }
}

/// Main TFTP server
pub struct TftpServer {
    config: TftpServerConfig,
    socket: Option<UdpSocket>,
}

impl TftpServer {
    /// Create a new TFTP server with the given configuration
    pub fn new(config: TftpServerConfig) -> Self {
        Self { config, socket: None }
    }

    /// Create a new TFTP server with default configuration
    pub fn with_defaults() -> Self {
        Self::new(TftpServerConfig::default())
    }

    /// Create a new TFTP server with custom bind address and root directory
    pub fn with_config(bind_address: String, root_directory: PathBuf) -> Self {
        let mut config = TftpServerConfig {
            bind_address,
            root_directory: root_directory.clone(),
            ..Default::default()
        };
        config.transfer_config.root_dir = root_directory;

        Self::new(config)
    }

    /// Get the server's configuration
    pub fn config(&self) -> &TftpServerConfig {
        &self.config
    }

    /// Get a mutable reference to the server's configuration
    pub fn config_mut(&mut self) -> &mut TftpServerConfig {
        &mut self.config
    }

    /// Start the TFTP server and run the main loop
    pub async fn run(&mut self) -> Result<()> {
        // Bind the socket
        let socket = UdpSocket::bind(&self.config.bind_address)
            .await
            .context("Failed to bind TFTP server socket")?;

        let local_addr = socket.local_addr().context("Failed to get local address")?;
        tracing::info!(
            "TFTP server listening on {}, serving files from {}",
            local_addr,
            self.config.root_directory.display()
        );

        self.socket = Some(socket);
        self.serve().await
    }

    /// Get the local address the server is bound to (if running)
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.as_ref().and_then(|s| s.local_addr().ok())
    }

    /// Main server loop
    async fn serve(&self) -> Result<()> {
        let socket = self.socket.as_ref().expect("Server must be bound before serving");

        let mut buffer = [0u8; 2048]; // Buffer for incoming packets

        loop {
            // Receive a packet
            let (len, client_addr) = socket.recv_from(&mut buffer).await?;
            tracing::debug!("Received packet from {}", client_addr);

            if len < 2 {
                tracing::debug!("Received packet too short");
                continue;
            }

            let packet = &buffer[..len];

            let tftp_opcode = get_tftp_opcode(packet);
            match tftp_opcode {
                Some(TftpOpcode::ReadRequest) => {
                    self.handle_read_request_packet(packet, client_addr).await;
                }
                Some(opcode) => {
                    tracing::debug!("Ignoring unsupported opcode {:?} from {}", opcode, client_addr);
                }
                None => {
                    tracing::debug!("Received malformed packet from {}", client_addr);
                }
            }
        }
    }

    /// Handle an incoming RRQ packet
    async fn handle_read_request_packet(&self, packet: &[u8], client: SocketAddr) {
        match parse_rrq(packet) {
            Ok((filename, mode, options)) => {
                tracing::info!(
                    "RRQ for '{}' in {} mode from {} (options: {:?})",
                    filename,
                    mode,
                    client,
                    options
                );

                // Spawn a task to handle this request
                let config = self.config.transfer_config.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_read_request(client, filename.clone(), mode, &options, &config).await {
                        tracing::warn!("Failed to transfer '{}' to {}: {}", filename, client, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Failed to parse RRQ from {}: {}", client, e);
            }
        }
    }
}

/// Run a TFTP server with the given bind address and root directory
///
/// This is a convenience function that creates and runs a TFTP server.
pub async fn run_tftp_server(bind_address: String, root_directory: PathBuf, local_bind: Option<IpAddr>) -> Result<()> {
    let mut server = TftpServer::with_config(bind_address, root_directory);
    server.config.transfer_config.local_bind = local_bind;
    server.run().await
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_tftp_server_config_default() {
        let config = TftpServerConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:6969");
        assert_eq!(config.root_directory, PathBuf::from("./tftp_root"));
    }

    #[test]
    fn test_tftp_server_creation() {
        let server = TftpServer::with_defaults();
        assert_eq!(server.config().bind_address, "0.0.0.0:6969");
        assert!(server.local_addr().is_none()); // Not bound yet

        let custom_server = TftpServer::with_config("127.0.0.1:9999".to_string(), PathBuf::from("/tmp/tftp"));
        assert_eq!(custom_server.config().bind_address, "127.0.0.1:9999");
        assert_eq!(custom_server.config().root_directory, PathBuf::from("/tmp/tftp"));
    }

    #[tokio::test]
    async fn test_server_bind() {
        let mut server = TftpServer::with_config(
            "127.0.0.1:0".to_string(), // Use ephemeral port
            PathBuf::from("./tftp_root"),
        );

        // Start server in background with timeout
        let server_task = tokio::spawn(async move { server.run().await });

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Stop the server
        server_task.abort();

        // Task should be aborted
        let result = server_task.await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_server_local_addr() {
        use tokio::net::UdpSocket;

        // Create a server that binds to an ephemeral port
        let temp_dir = tempdir().unwrap();
        let config = TftpServerConfig {
            bind_address: "127.0.0.1:0".to_string(),
            root_directory: temp_dir.path().to_path_buf(),
            transfer_config: TransferConfig::default(),
        };

        let mut server = TftpServer::new(config);

        // Before binding, local_addr should be None
        assert!(server.local_addr().is_none());

        // Bind socket manually to test local_addr
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected_addr = socket.local_addr().unwrap();
        server.socket = Some(socket);

        // After binding, local_addr should return the bound address
        assert_eq!(server.local_addr(), Some(expected_addr));
    }
}
