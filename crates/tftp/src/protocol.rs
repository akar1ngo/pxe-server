//! TFTP Protocol Implementation
//!
//! This module contains the core TFTP protocol functionality including
//! packet parsing, building, and protocol constants.
//!
//! # TFTP Protocol Overview
//!
//! TFTP (Trivial File Transfer Protocol) is defined in RFC 1350 with extensions
//! in various other RFCs. It's a simple protocol designed for environments where
//! a full FTP implementation is not practical.
//!
//! The protocol supports:
//! - Read Request (RRQ) - Request to read a file from the server
//! - Write Request (WRQ) - Request to write a file to the server
//! - Data packets - Transfer file content in blocks
//! - Acknowledgment (ACK) - Confirm receipt of data blocks
//! - Error packets - Report errors during transfer
//! - Option acknowledgment (OACK) - Negotiate transfer options
//!
//! # Security Considerations
//!
//! This implementation includes protection against:
//! - Path traversal attacks (../ sequences)
//! - Null byte injection
//! - Buffer overflow attacks
//! - Directory enumeration

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Result, anyhow};

/// TFTP Protocol Opcodes
///
/// These opcodes identify the type of TFTP packet being sent or received.
/// Each opcode corresponds to a specific packet format as defined in RFC 1350.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftpOpcode {
    /// Read Request (RRQ) - Opcode 1
    ///
    /// Client requests to read a file from the server. Contains filename,
    /// transfer mode, and optional extension parameters.
    ///
    /// Packet format: | Opcode | Filename | 0 | Mode | 0 | \[Options\] |
    ReadRequest = 1,

    /// Write Request (WRQ) - Opcode 2
    ///
    /// Client requests to write a file to the server. Contains filename,
    /// transfer mode, and optional extension parameters.
    ///
    /// Note: Write requests are not currently supported by this server.
    ///
    /// Packet format: | Opcode | Filename | 0 | Mode | 0 | \[Options\] |
    WriteRequest = 2,

    /// Data Packet (DATA) - Opcode 3
    ///
    /// Contains a block of file data being transferred. Each data packet
    /// contains a 2-byte block number and up to 512 bytes of data by default
    /// (or negotiated block size).
    ///
    /// The last packet of a transfer may contain less than the full block size.
    ///
    /// Packet format: | Opcode | Block# | Data |
    Data = 3,

    /// Acknowledgment (ACK) - Opcode 4
    ///
    /// Acknowledges receipt of a data packet. Contains the block number
    /// of the data packet being acknowledged.
    ///
    /// Special case: ACK with block number 0 acknowledges an OACK packet.
    ///
    /// Packet format: | Opcode | Block# |
    Acknowledgment = 4,

    /// Error Packet (ERROR) - Opcode 5
    ///
    /// Reports an error condition. Contains an error code and human-readable
    /// error message. Terminates the current transfer.
    ///
    /// Packet format: | Opcode | ErrorCode | ErrMsg | 0 |
    Error = 5,

    /// Option Acknowledgment (OACK) - Opcode 6
    ///
    /// Used to acknowledge and negotiate TFTP options as defined in RFC 2347.
    /// Contains the negotiated option values.
    ///
    /// Common options include:
    /// - `blksize`: Block size (RFC 2348)
    /// - `tsize`: Transfer size (RFC 2349)
    /// - `timeout`: Timeout interval (RFC 2349)
    ///
    /// Packet format: | Opcode | Opt1 | 0 | Value1 | 0 | ... |
    OptionAck = 6,
}

impl TftpOpcode {
    /// Convert a u16 value to a TftpOpcode
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpOpcode;
    ///
    /// assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::ReadRequest));
    /// assert_eq!(TftpOpcode::from_u16(99), None);
    /// ```
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::ReadRequest),
            2 => Some(Self::WriteRequest),
            3 => Some(Self::Data),
            4 => Some(Self::Acknowledgment),
            5 => Some(Self::Error),
            6 => Some(Self::OptionAck),
            _ => None,
        }
    }

    /// Convert the opcode to its u16 representation
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpOpcode;
    ///
    /// assert_eq!(TftpOpcode::ReadRequest.as_u16(), 1);
    /// assert_eq!(TftpOpcode::Data.as_u16(), 3);
    /// ```
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get the human-readable name of the opcode
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpOpcode;
    ///
    /// assert_eq!(TftpOpcode::ReadRequest.name(), "RRQ");
    /// assert_eq!(TftpOpcode::Data.name(), "DATA");
    /// ```
    pub fn name(self) -> &'static str {
        match self {
            Self::ReadRequest => "RRQ",
            Self::WriteRequest => "WRQ",
            Self::Data => "DATA",
            Self::Acknowledgment => "ACK",
            Self::Error => "ERROR",
            Self::OptionAck => "OACK",
        }
    }
}

impl From<TftpOpcode> for u16 {
    fn from(opcode: TftpOpcode) -> Self {
        opcode.as_u16()
    }
}

impl fmt::Display for TftpOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// TFTP Error Codes
///
/// Standard error codes as defined in RFC 1350, with additional codes
/// from various TFTP extensions and implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftpErrorCode {
    /// Error code 0: Not defined
    ///
    /// Generic error condition. The error message should provide details.
    NotDefined = 0,

    /// Error code 1: File not found
    ///
    /// The requested file does not exist on the server.
    FileNotFound = 1,

    /// Error code 2: Access violation
    ///
    /// Client lacks permission to access the requested file or operation.
    /// This includes attempts to write to read-only locations or access
    /// files outside the server's allowed directory tree.
    AccessViolation = 2,

    /// Error code 3: Disk full or allocation exceeded
    ///
    /// No more space available on the server to complete a write operation.
    DiskFull = 3,

    /// Error code 4: Illegal TFTP operation
    ///
    /// The requested operation is not supported or malformed.
    IllegalOperation = 4,

    /// Error code 5: Unknown transfer ID
    ///
    /// Packet received from an unknown source port or unexpected client.
    UnknownTransferId = 5,

    /// Error code 6: File already exists
    ///
    /// Attempted to create a file that already exists when it shouldn't be overwritten.
    FileAlreadyExists = 6,

    /// Error code 7: No such user
    ///
    /// User-based authentication failed or user does not exist.
    NoSuchUser = 7,

    /// Error code 8: Option negotiation failed
    ///
    /// Client and server could not agree on transfer options.
    /// This is an extension error code not in the original RFC.
    OptionNegotiationFailed = 8,
}

impl TftpErrorCode {
    /// Convert a u16 value to a TftpErrorCode
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpErrorCode;
    ///
    /// assert_eq!(TftpErrorCode::from_u16(1), Some(TftpErrorCode::FileNotFound));
    /// assert_eq!(TftpErrorCode::from_u16(99), None);
    /// ```
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::NotDefined),
            1 => Some(Self::FileNotFound),
            2 => Some(Self::AccessViolation),
            3 => Some(Self::DiskFull),
            4 => Some(Self::IllegalOperation),
            5 => Some(Self::UnknownTransferId),
            6 => Some(Self::FileAlreadyExists),
            7 => Some(Self::NoSuchUser),
            8 => Some(Self::OptionNegotiationFailed),
            _ => None,
        }
    }

    /// Convert the error code to its u16 representation
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpErrorCode;
    ///
    /// assert_eq!(TftpErrorCode::FileNotFound.as_u16(), 1);
    /// assert_eq!(TftpErrorCode::AccessViolation.as_u16(), 2);
    /// ```
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Get the default error message for this error code
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpErrorCode;
    ///
    /// assert_eq!(TftpErrorCode::FileNotFound.default_message(), "File not found");
    /// assert_eq!(TftpErrorCode::AccessViolation.default_message(), "Access violation");
    /// ```
    pub fn default_message(self) -> &'static str {
        match self {
            Self::NotDefined => "Undefined error",
            Self::FileNotFound => "File not found",
            Self::AccessViolation => "Access violation",
            Self::DiskFull => "Disk full or allocation exceeded",
            Self::IllegalOperation => "Illegal TFTP operation",
            Self::UnknownTransferId => "Unknown transfer ID",
            Self::FileAlreadyExists => "File already exists",
            Self::NoSuchUser => "No such user",
            Self::OptionNegotiationFailed => "Option negotiation failed",
        }
    }
}

impl From<TftpErrorCode> for u16 {
    fn from(error_code: TftpErrorCode) -> Self {
        error_code.as_u16()
    }
}

impl fmt::Display for TftpErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.default_message(), self.as_u16())
    }
}

/// TFTP Transfer Modes
///
/// Transfer modes define how data is processed during transmission.
/// Only binary (octet) mode is commonly used in modern implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransferMode {
    /// Binary mode (octet)
    ///
    /// Data is transferred as-is without any character set conversion.
    /// This is the recommended mode for all file types including text files.
    ///
    /// Mode string: "octet"
    Octet,

    /// Text mode (netascii)
    ///
    /// Data is converted between local text format and NETASCII format.
    /// NETASCII uses CR-LF for line endings. This mode is rarely used
    /// in practice due to encoding complexities.
    ///
    /// Mode string: "netascii"
    NetAscii,
}

impl TransferMode {
    /// Parse a transfer mode from a string
    ///
    /// The comparison is case-insensitive.
    ///
    /// # Examples
    /// ```
    /// use tftp::TransferMode;
    ///
    /// assert_eq!("octet".parse::<TransferMode>(), Ok(TransferMode::Octet));
    /// assert_eq!("NETASCII".parse::<TransferMode>(), Ok(TransferMode::NetAscii));
    /// assert!("binary".parse::<TransferMode>().is_err());
    /// ```
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "octet" => Some(Self::Octet),
            "netascii" => Some(Self::NetAscii),
            _ => None,
        }
    }

    /// Get the string representation of the transfer mode
    ///
    /// # Examples
    /// ```
    /// use tftp::TransferMode;
    ///
    /// assert_eq!(TransferMode::Octet.as_str(), "octet");
    /// assert_eq!(TransferMode::NetAscii.as_str(), "netascii");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Octet => "octet",
            Self::NetAscii => "netascii",
        }
    }

    /// Check if this transfer mode is supported by the server
    ///
    /// Currently only octet mode is fully supported.
    ///
    /// # Examples
    /// ```
    /// use tftp::TransferMode;
    ///
    /// assert!(TransferMode::Octet.is_supported());
    /// assert!(!TransferMode::NetAscii.is_supported()); // Limited support
    /// ```
    pub fn is_supported(self) -> bool {
        match self {
            Self::Octet => true,
            Self::NetAscii => false, // TODO: Enable when netascii support is complete
        }
    }
}

impl FromStr for TransferMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_opt(s).ok_or_else(|| format!("Unsupported transfer mode: {}", s))
    }
}

impl fmt::Display for TransferMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Block Size Configuration
///
/// Manages TFTP block size settings including defaults, limits, and validation.
/// Block size negotiation is defined in RFC 2348.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSizeConfig {
    /// The negotiated block size in bytes
    pub size: usize,
}

impl BlockSizeConfig {
    /// Default TFTP block size (512 bytes)
    pub const DEFAULT: usize = 512;

    /// Maximum allowed block size (1400 bytes)
    ///
    /// This limit ensures packets fit within standard MTU sizes while
    /// leaving room for UDP/IP headers and avoiding fragmentation.
    pub const MAX: usize = 1400;

    /// Create a new BlockSizeConfig with the default size
    ///
    /// # Examples
    /// ```
    /// use tftp::BlockSizeConfig;
    ///
    /// let config = BlockSizeConfig::default_size();
    /// assert_eq!(config.size, 512);
    /// ```
    pub fn default_size() -> Self {
        Self { size: Self::DEFAULT }
    }

    /// Create a BlockSizeConfig from an option value, with validation
    ///
    /// # Arguments
    /// * `value` - The requested block size as a string
    ///
    /// # Returns
    /// * Valid block size if the value is acceptable
    /// * Default block size if the value is invalid or out of range
    ///
    /// # Examples
    /// ```
    /// use tftp::BlockSizeConfig;
    ///
    /// let config = BlockSizeConfig::from_option("1024");
    /// assert_eq!(config.size, 1024);
    ///
    /// let config = BlockSizeConfig::from_option("2000"); // Too large
    /// assert_eq!(config.size, 1400); // Clamped to max
    ///
    /// let config = BlockSizeConfig::from_option("invalid");
    /// assert_eq!(config.size, 512); // Falls back to default
    /// ```
    pub fn from_option(value: &str) -> Self {
        let size = value
            .parse::<usize>()
            .ok()
            .map(|n| std::cmp::min(n, Self::MAX))
            .filter(|&n| n > 0)
            .unwrap_or(Self::DEFAULT);

        Self { size }
    }

    /// Parse block size from TFTP options map
    ///
    /// # Arguments
    /// * `options` - Map of TFTP option names to values
    ///
    /// # Examples
    /// ```
    /// use std::collections::HashMap;
    /// use tftp::BlockSizeConfig;
    ///
    /// let mut options = HashMap::new();
    /// options.insert("blksize".to_string(), "1024".to_string());
    ///
    /// let config = BlockSizeConfig::from_options(&options);
    /// assert_eq!(config.size, 1024);
    /// ```
    pub fn from_options(options: &HashMap<String, String>) -> Self {
        options
            .get("blksize")
            .map(|s| Self::from_option(s))
            .unwrap_or_else(Self::default_size)
    }

    /// Check if the block size was negotiated (differs from default)
    ///
    /// # Examples
    /// ```
    /// use tftp::BlockSizeConfig;
    ///
    /// let default_config = BlockSizeConfig::default_size();
    /// assert!(!default_config.is_negotiated());
    ///
    /// let custom_config = BlockSizeConfig::from_option("1024");
    /// assert!(custom_config.is_negotiated());
    /// ```
    pub fn is_negotiated(self) -> bool {
        self.size != Self::DEFAULT
    }
}

impl Default for BlockSizeConfig {
    fn default() -> Self {
        Self::default_size()
    }
}

impl fmt::Display for BlockSizeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.size)
    }
}

/// TFTP Request (RRQ/WRQ) representation
#[derive(Debug, Clone, PartialEq)]
pub struct TftpRequest {
    /// The request opcode (RRQ or WRQ)
    pub opcode: TftpOpcode,
    /// Requested filename
    pub filename: String,
    /// Transfer mode
    pub mode: TransferMode,
    /// Negotiated options
    pub options: HashMap<String, String>,
}

impl TftpRequest {
    /// Create a new read request
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpRequest, TransferMode};
    ///
    /// let request = TftpRequest::read_request("boot.img", TransferMode::Octet);
    /// assert_eq!(request.filename, "boot.img");
    /// assert_eq!(request.mode, TransferMode::Octet);
    /// ```
    pub fn read_request(filename: impl Into<String>, mode: TransferMode) -> Self {
        Self {
            opcode: TftpOpcode::ReadRequest,
            filename: filename.into(),
            mode,
            options: HashMap::new(),
        }
    }

    /// Add an option to the request
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpRequest, TransferMode};
    ///
    /// let mut request = TftpRequest::read_request("boot.img", TransferMode::Octet);
    /// request.with_option("blksize", "1400");
    ///
    /// assert_eq!(request.options.get("blksize"), Some(&"1400".to_string()));
    /// ```
    pub fn with_option(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Get the negotiated block size for this request
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpRequest, TransferMode};
    ///
    /// let mut request = TftpRequest::read_request("boot.img", TransferMode::Octet);
    /// request.with_option("blksize", "1024");
    ///
    /// let block_size = request.block_size();
    /// assert_eq!(block_size.size, 1024);
    /// ```
    pub fn block_size(&self) -> BlockSizeConfig {
        BlockSizeConfig::from_options(&self.options)
    }
}

/// TFTP Data packet representation
#[derive(Debug, Clone, PartialEq)]
pub struct TftpData {
    /// Block number (1-indexed)
    pub block: u16,
    /// Data payload
    pub data: Vec<u8>,
}

impl TftpData {
    /// Create a new data packet
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpData;
    ///
    /// let data = TftpData::new(1, b"Hello, TFTP!");
    /// assert_eq!(data.block, 1);
    /// assert_eq!(data.data, b"Hello, TFTP!");
    /// ```
    pub fn new(block: u16, data: impl Into<Vec<u8>>) -> Self {
        Self {
            block,
            data: data.into(),
        }
    }

    /// Check if this is the last block of a transfer
    ///
    /// A block is considered the last if it's smaller than the negotiated block size.
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpData, BlockSizeConfig};
    ///
    /// let small_data = TftpData::new(1, vec![0; 100]);
    /// let large_data = TftpData::new(1, vec![0; 512]);
    /// let config = BlockSizeConfig::default_size();
    ///
    /// assert!(small_data.is_last_block(&config));
    /// assert!(!large_data.is_last_block(&config));
    /// ```
    pub fn is_last_block(&self, config: &BlockSizeConfig) -> bool {
        self.data.len() < config.size
    }
}

/// TFTP ACK packet representation
#[derive(Debug, Clone, PartialEq)]
pub struct TftpAck {
    /// Block number being acknowledged
    pub block: u16,
}

impl TftpAck {
    /// Create a new ACK packet
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpAck;
    ///
    /// let ack = TftpAck::new(42);
    /// assert_eq!(ack.block, 42);
    /// ```
    pub fn new(block: u16) -> Self {
        Self { block }
    }

    /// Create an ACK for block 0 (OACK acknowledgment)
    ///
    /// # Examples
    /// ```
    /// use tftp::TftpAck;
    ///
    /// let oack_ack = TftpAck::oack_ack();
    /// assert_eq!(oack_ack.block, 0);
    /// ```
    pub fn oack_ack() -> Self {
        Self::new(0)
    }
}

/// TFTP Error packet representation
#[derive(Debug, Clone, PartialEq)]
pub struct TftpError {
    /// Error code
    pub code: TftpErrorCode,
    /// Human-readable error message
    pub message: String,
}

impl TftpError {
    /// Create a new error packet with a custom message
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpError, TftpErrorCode};
    ///
    /// let error = TftpError::new(TftpErrorCode::FileNotFound, "boot.img not found");
    /// assert_eq!(error.code, TftpErrorCode::FileNotFound);
    /// assert_eq!(error.message, "boot.img not found");
    /// ```
    pub fn new(code: TftpErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Create a new error packet with the default message for the error code
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpError, TftpErrorCode};
    ///
    /// let error = TftpError::with_default_message(TftpErrorCode::AccessViolation);
    /// assert_eq!(error.code, TftpErrorCode::AccessViolation);
    /// assert_eq!(error.message, "Access violation");
    /// ```
    pub fn with_default_message(code: TftpErrorCode) -> Self {
        Self::new(code, code.default_message())
    }

    /// Convenience method for file not found error
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpError, TftpErrorCode};
    ///
    /// let error = TftpError::file_not_found();
    /// assert_eq!(error.code, TftpErrorCode::FileNotFound);
    /// ```
    pub fn file_not_found() -> Self {
        Self::with_default_message(TftpErrorCode::FileNotFound)
    }

    /// Convenience method for access violation error
    ///
    /// # Examples
    /// ```
    /// use tftp::{TftpError, TftpErrorCode};
    ///
    /// let error = TftpError::access_violation();
    /// assert_eq!(error.code, TftpErrorCode::AccessViolation);
    /// ```
    pub fn access_violation() -> Self {
        Self::with_default_message(TftpErrorCode::AccessViolation)
    }
}

impl fmt::Display for TftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Find the next null byte in a buffer starting from a given position
pub fn find_zero(buf: &[u8], start: usize) -> Option<usize> {
    buf[start..].iter().position(|&b| b == 0).map(|pos| start + pos)
}

/// Parse a TFTP Read Request (RRQ) packet
///
/// Returns (filename, mode, options) tuple
pub fn parse_rrq(buf: &[u8]) -> Result<(String, String, HashMap<String, String>)> {
    if buf.len() < 4 {
        return Err(anyhow!("RRQ too short"));
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    if opcode != TftpOpcode::ReadRequest.as_u16() {
        return Err(anyhow!("Not an RRQ packet"));
    }

    let mut i = 2;

    // Parse filename
    let fname_end = find_zero(buf, i).ok_or_else(|| anyhow!("filename not terminated"))?;
    let filename = std::str::from_utf8(&buf[i..fname_end])?.to_string();
    i = fname_end + 1;

    // Parse mode
    let mode_end = find_zero(buf, i).ok_or_else(|| anyhow!("mode not terminated"))?;
    let mode = std::str::from_utf8(&buf[i..mode_end])?.to_ascii_lowercase();
    i = mode_end + 1;

    // Parse options
    let mut opts = HashMap::new();
    while i < buf.len() {
        let key_end = find_zero(buf, i).ok_or_else(|| anyhow!("option key not terminated"))?;
        let key = std::str::from_utf8(&buf[i..key_end])?.to_string();
        i = key_end + 1;

        if i >= buf.len() {
            break;
        }

        let val_end = find_zero(buf, i).ok_or_else(|| anyhow!("option value not terminated"))?;
        let val = std::str::from_utf8(&buf[i..val_end])?.to_string();
        i = val_end + 1;

        opts.insert(key, val);
    }

    Ok((filename, mode, opts))
}

/// Parse a TFTP ACK packet
pub fn parse_ack(buf: &[u8]) -> Result<u16> {
    if buf.len() < 4 {
        return Err(anyhow!("ACK too short"));
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    if opcode != TftpOpcode::Acknowledgment.as_u16() {
        return Err(anyhow!("Not an ACK packet"));
    }

    Ok(u16::from_be_bytes([buf[2], buf[3]]))
}

/// Parse a TFTP Error packet
pub fn parse_error(buf: &[u8]) -> Result<(u16, String)> {
    if buf.len() < 4 {
        return Err(anyhow!("Error packet too short"));
    }

    let opcode = u16::from_be_bytes([buf[0], buf[1]]);
    if opcode != TftpOpcode::Error.as_u16() {
        return Err(anyhow!("Not an Error packet"));
    }

    let code = u16::from_be_bytes([buf[2], buf[3]]);
    let message = if buf.len() > 4 {
        let msg_bytes = &buf[4..];
        // Find null terminator or use entire remaining buffer
        let end = msg_bytes.iter().position(|&b| b == 0).unwrap_or(msg_bytes.len());
        std::str::from_utf8(&msg_bytes[..end])?.to_string()
    } else {
        String::new()
    };

    Ok((code, message))
}

/// Build a TFTP Data packet
pub fn build_data(block: u16, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + data.len());
    v.extend_from_slice(&TftpOpcode::Data.as_u16().to_be_bytes());
    v.extend_from_slice(&block.to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// Build a TFTP ACK packet
pub fn build_ack(block: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(4);
    v.extend_from_slice(&TftpOpcode::Acknowledgment.as_u16().to_be_bytes());
    v.extend_from_slice(&block.to_be_bytes());
    v
}

/// Build a TFTP Error packet
pub fn build_error(code: u16, msg: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + msg.len() + 1);
    v.extend_from_slice(&TftpOpcode::Error.as_u16().to_be_bytes());
    v.extend_from_slice(&code.to_be_bytes());
    v.extend_from_slice(msg.as_bytes());
    v.push(0);
    v
}

/// Build a TFTP OACK (Option Acknowledgment) packet
pub fn build_oack(opts: &HashMap<String, String>) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&TftpOpcode::OptionAck.as_u16().to_be_bytes());

    for (key, val) in opts {
        v.extend_from_slice(key.as_bytes());
        v.push(0);
        v.extend_from_slice(val.as_bytes());
        v.push(0);
    }

    v
}

/// Get the opcode from a TFTP packet
pub fn get_opcode(buf: &[u8]) -> Option<u16> {
    if buf.len() >= 2 {
        Some(u16::from_be_bytes([buf[0], buf[1]]))
    } else {
        None
    }
}

/// Get the TFTP opcode enum from a packet buffer
pub fn get_tftp_opcode(buf: &[u8]) -> Option<TftpOpcode> {
    get_opcode(buf).and_then(TftpOpcode::from_u16)
}

/// Convert file data from binary to netascii format
/// This is used when mode is "netascii"
pub fn convert_to_netascii(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < data.len() {
        match data[i] {
            // Handle CR - check if followed by LF
            b'\r' => {
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    // CR-LF stays as CR-LF
                    result.push(b'\r');
                    result.push(b'\n');
                    i += 2;
                } else {
                    // Standalone CR becomes CR-NULL
                    result.push(b'\r');
                    result.push(b'\0');
                    i += 1;
                }
            }
            // Standalone LF becomes CR-LF
            b'\n' => {
                result.push(b'\r');
                result.push(b'\n');
                i += 1;
            }
            // Regular byte
            _ => {
                result.push(data[i]);
                i += 1;
            }
        }
    }

    result
}

/// Convert file data from netascii to binary format
/// This is used when receiving files in netascii mode
pub fn convert_from_netascii(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < data.len() {
        match data[i] {
            b'\r' => {
                if i + 1 < data.len() {
                    match data[i + 1] {
                        b'\n' => {
                            // CR-LF -> LF
                            result.push(b'\n');
                            i += 2;
                        }
                        b'\0' => {
                            // CR-NULL -> CR
                            result.push(b'\r');
                            i += 2;
                        }
                        _ => {
                            // Standalone CR (shouldn't happen in valid netascii)
                            result.push(b'\r');
                            i += 1;
                        }
                    }
                } else {
                    // CR at end of data
                    result.push(b'\r');
                    i += 1;
                }
            }
            _ => {
                result.push(data[i]);
                i += 1;
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tftp_opcode_conversion() {
        assert_eq!(TftpOpcode::ReadRequest.as_u16(), 1);
        assert_eq!(TftpOpcode::Data.as_u16(), 3);
        assert_eq!(TftpOpcode::from_u16(1), Some(TftpOpcode::ReadRequest));
        assert_eq!(TftpOpcode::from_u16(99), None);
    }

    #[test]
    fn test_tftp_error_code_conversion() {
        assert_eq!(TftpErrorCode::FileNotFound.as_u16(), 1);
        assert_eq!(TftpErrorCode::from_u16(1), Some(TftpErrorCode::FileNotFound));
        assert_eq!(TftpErrorCode::FileNotFound.default_message(), "File not found");
    }

    #[test]
    fn test_transfer_mode() {
        assert_eq!(TransferMode::from_str_opt("octet"), Some(TransferMode::Octet));
        assert_eq!(TransferMode::from_str_opt("NETASCII"), Some(TransferMode::NetAscii));
        assert_eq!(TransferMode::from_str_opt("invalid"), None);

        // Test FromStr trait implementation
        assert_eq!("octet".parse::<TransferMode>(), Ok(TransferMode::Octet));
        assert_eq!("NETASCII".parse::<TransferMode>(), Ok(TransferMode::NetAscii));
        assert!("invalid".parse::<TransferMode>().is_err());

        assert!(TransferMode::Octet.is_supported());
        assert!(!TransferMode::NetAscii.is_supported());
    }

    #[test]
    fn test_block_size_config() {
        let config = BlockSizeConfig::default_size();
        assert_eq!(config.size, 512);
        assert!(!config.is_negotiated());

        let custom = BlockSizeConfig::from_option("1024");
        assert_eq!(custom.size, 1024);
        assert!(custom.is_negotiated());

        let too_large = BlockSizeConfig::from_option("2000");
        assert_eq!(too_large.size, 1400); // Clamped to max

        let invalid = BlockSizeConfig::from_option("invalid");
        assert_eq!(invalid.size, 512); // Falls back to default
    }

    #[test]
    fn test_tftp_packet_structures() {
        let request = TftpRequest::read_request("test.txt", TransferMode::Octet);
        assert_eq!(request.opcode, TftpOpcode::ReadRequest);
        assert_eq!(request.filename, "test.txt");
        assert_eq!(request.mode, TransferMode::Octet);

        let data = TftpData::new(1, b"Hello");
        assert_eq!(data.block, 1);
        assert_eq!(data.data, b"Hello");

        let ack = TftpAck::new(42);
        assert_eq!(ack.block, 42);

        let error = TftpError::file_not_found();
        assert_eq!(error.code, TftpErrorCode::FileNotFound);
    }

    #[test]
    fn test_find_zero() {
        let buf = b"hello\0world\0";
        assert_eq!(find_zero(buf, 0), Some(5));
        assert_eq!(find_zero(buf, 6), Some(11));
        assert_eq!(find_zero(buf, 12), None);
    }

    #[test]
    fn test_parse_rrq_basic() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TftpOpcode::ReadRequest.as_u16().to_be_bytes());
        buf.extend_from_slice(b"test.txt\0");
        buf.extend_from_slice(b"octet\0");

        let (filename, mode, opts) = parse_rrq(&buf).unwrap();
        assert_eq!(filename, "test.txt");
        assert_eq!(mode, "octet");
        assert!(opts.is_empty());
    }

    #[test]
    fn test_parse_rrq_with_options() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TftpOpcode::ReadRequest.as_u16().to_be_bytes());
        buf.extend_from_slice(b"boot.img\0");
        buf.extend_from_slice(b"octet\0");
        buf.extend_from_slice(b"blksize\0");
        buf.extend_from_slice(b"1400\0");
        buf.extend_from_slice(b"tsize\0");
        buf.extend_from_slice(b"0\0");

        let (filename, mode, opts) = parse_rrq(&buf).unwrap();
        assert_eq!(filename, "boot.img");
        assert_eq!(mode, "octet");
        assert_eq!(opts.get("blksize"), Some(&"1400".to_string()));
        assert_eq!(opts.get("tsize"), Some(&"0".to_string()));
    }

    #[test]
    fn test_build_data() {
        let data = b"Hello, TFTP!";
        let packet = build_data(1, data);

        assert_eq!(packet.len(), 4 + data.len());
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), TftpOpcode::Data.as_u16());
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 1);
        assert_eq!(&packet[4..], data);
    }

    #[test]
    fn test_build_ack() {
        let packet = build_ack(42);

        assert_eq!(packet.len(), 4);
        assert_eq!(
            u16::from_be_bytes([packet[0], packet[1]]),
            TftpOpcode::Acknowledgment.as_u16()
        );
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 42);
    }

    #[test]
    fn test_build_error() {
        let packet = build_error(TftpErrorCode::FileNotFound.as_u16(), "File not found");

        assert!(packet.len() > 4);
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), TftpOpcode::Error.as_u16());
        assert_eq!(
            u16::from_be_bytes([packet[2], packet[3]]),
            TftpErrorCode::FileNotFound.as_u16()
        );
        assert_eq!(&packet[4..packet.len() - 1], b"File not found");
        assert_eq!(packet[packet.len() - 1], 0);
    }

    #[test]
    fn test_build_oack() {
        let mut opts = HashMap::new();
        opts.insert("blksize".to_string(), "1400".to_string());
        opts.insert("tsize".to_string(), "1024".to_string());

        let packet = build_oack(&opts);

        assert!(packet.len() > 2);
        assert_eq!(
            u16::from_be_bytes([packet[0], packet[1]]),
            TftpOpcode::OptionAck.as_u16()
        );

        // The packet should contain both options, but order may vary due to HashMap
        let packet_str = String::from_utf8_lossy(&packet[2..]);
        #[allow(clippy::octal_escapes)]
        {
            assert!(packet_str.contains("blksize\01400\0"));
            assert!(packet_str.contains("tsize\01024\0"));
        }
    }

    #[test]
    fn test_parse_ack() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TftpOpcode::Acknowledgment.as_u16().to_be_bytes());
        buf.extend_from_slice(&123u16.to_be_bytes());

        let block = parse_ack(&buf).unwrap();
        assert_eq!(block, 123);
    }

    #[test]
    fn test_parse_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TftpOpcode::Error.as_u16().to_be_bytes());
        buf.extend_from_slice(&TftpErrorCode::AccessViolation.as_u16().to_be_bytes());
        buf.extend_from_slice(b"Access denied\0");

        let (code, message) = parse_error(&buf).unwrap();
        assert_eq!(code, TftpErrorCode::AccessViolation.as_u16());
        assert_eq!(message, "Access denied");
    }

    #[test]
    fn test_get_opcode() {
        let data_packet = build_data(1, b"test");
        assert_eq!(get_opcode(&data_packet), Some(TftpOpcode::Data.as_u16()));
        assert_eq!(get_tftp_opcode(&data_packet), Some(TftpOpcode::Data));

        let ack_packet = build_ack(5);
        assert_eq!(get_opcode(&ack_packet), Some(TftpOpcode::Acknowledgment.as_u16()));

        assert_eq!(get_opcode(&[]), None);
        assert_eq!(get_opcode(&[1]), None);
    }

    #[test]
    fn test_convert_to_netascii() {
        let input = b"Hello\nWorld\r\nTest\r";
        let expected = b"Hello\r\nWorld\r\nTest\r\0";
        let result = convert_to_netascii(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_from_netascii() {
        let input = b"Hello\r\nWorld\r\0Test";
        let expected = b"Hello\nWorld\rTest";
        let result = convert_from_netascii(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_netascii_round_trip() {
        // Test simple LF-only text (LF becomes CR-LF in netascii, then back to LF)
        let simple_input = b"Line1\nLine2\nLine3";
        let simple_netascii = convert_to_netascii(simple_input);
        let simple_back = convert_from_netascii(&simple_netascii);
        assert_eq!(simple_back, simple_input);

        // Test CR-LF sequences (already proper netascii, stays CR-LF)
        let crlf_input = b"Line1\r\nLine2\r\nLine3";
        let crlf_netascii = convert_to_netascii(crlf_input);
        let crlf_back = convert_from_netascii(&crlf_netascii);
        // CR-LF in input becomes LF in output (netascii CR-LF -> binary LF)
        let expected_back = b"Line1\nLine2\nLine3";
        assert_eq!(crlf_back, expected_back);

        // Test standalone CR (gets converted to CR-NULL, then back to CR)
        let cr_input = b"Line1\rLine2";
        let cr_netascii = convert_to_netascii(cr_input);
        let cr_back = convert_from_netascii(&cr_netascii);
        assert_eq!(cr_back, cr_input);
    }
}
