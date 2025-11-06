//! PXE Server Library
//!
//! A lightweight PXE (Preboot Execution Environment) server providing both TFTP and ProxyDHCP services.
//!
//! This library provides a clean separation between TFTP server functionality and ProxyDHCP functionality,
//! making it easy to use either service independently or together.
//!
//! # Features
//!
//! - **TFTP Server**: Complete RFC 1350 implementation with extensions
//!   - Binary (octet) and text (netascii) transfer modes
//!   - Block size negotiation (RFC 2348)
//!   - Transfer size reporting (RFC 2349)
//!   - Path traversal protection
//!   - Concurrent transfers
//!
//! - **ProxyDHCP Server**: PXE boot support
//!   - BIOS and UEFI boot file serving
//!   - Vendor class identification
//!   - Integration with existing DHCP servers
//!

pub mod dhcp;
pub mod proxy_dhcp;
pub mod tftp;
pub mod util;
