//! TFTP (Trivial File Transfer Protocol) Implementation
//!
//! This module provides a complete TFTP server implementation with support for:
//! - Read requests (RRQ)
//! - Binary (octet) and text (netascii) transfer modes
//! - Block size negotiation (RFC 2348)
//! - Transfer size reporting (RFC 2349)
//! - Path traversal protection
//! - Concurrent transfers
//! - Well-documented protocol enums and types
//!
//! # Protocol Organization
//!
//! The TFTP protocol implementation is organized into well-documented enums and types:
//!
//! - [`TftpOpcode`] - All TFTP opcodes with comprehensive documentation
//! - [`TftpErrorCode`] - Standard error codes with default messages
//! - [`TransferMode`] - Transfer modes (octet/netascii) with validation
//! - [`BlockSizeConfig`] - Block size management with RFC 2348 compliance
//! - [`TftpRequest`], [`TftpData`], [`TftpAck`], [`TftpError`] - Structured packet types
//!
//! # Basic Server Usage
//!
//! ```rust,no_run
//! use pxe_server::tftp::{run_tftp_server, TftpServer, TftpServerConfig};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Simple usage with convenience function
//!     run_tftp_server(
//!         "0.0.0.0:69".to_string(),
//!         PathBuf::from("./tftp_root"),
//!         None,
//!     ).await?;
//!
//!     // Or use the server struct for more control
//!     let mut server = TftpServer::with_config(
//!         "127.0.0.1:6969".to_string(),
//!         PathBuf::from("./files")
//!     );
//!     server.run().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Working with Protocol Types
//!
//! ```rust
//! use pxe_server::tftp::{TftpOpcode, TftpErrorCode, TransferMode, BlockSizeConfig};
//! use std::collections::HashMap;
//!
//! // Create a read request
//! let mut request = pxe_server::tftp::TftpRequest::read_request("boot.img", TransferMode::Octet);
//! request.with_option("blksize", "1400");
//!
//! // Work with opcodes
//! assert_eq!(TftpOpcode::ReadRequest.as_u16(), 1);
//! assert_eq!(TftpOpcode::ReadRequest.name(), "RRQ");
//!
//! // Parse transfer modes safely
//! let mode: TransferMode = "octet".parse().unwrap();
//! assert!(mode.is_supported());
//!
//! // Handle block size negotiation
//! let mut options = HashMap::new();
//! options.insert("blksize".to_string(), "1024".to_string());
//! let block_config = BlockSizeConfig::from_options(&options);
//! assert_eq!(block_config.size, 1024);
//! assert!(block_config.is_negotiated());
//!
//! // Create error responses
//! let error = pxe_server::tftp::TftpError::file_not_found();
//! assert_eq!(error.code, TftpErrorCode::FileNotFound);
//! ```
//!
//! # Security Features
//!
//! - Path traversal attack prevention (../ sequences blocked)
//! - Null byte injection protection
//! - Buffer overflow protection with size limits
//! - Directory enumeration prevention
//! - Configurable root directory confinement

mod protocol;
mod server;
mod transfer;

pub use protocol::*;
pub use server::*;
pub use transfer::*;
