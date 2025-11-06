//! Proxy DHCP Server Module
//!
//! Implements a Proxy DHCP server that works alongside existing DHCP servers
//! to provide PXE boot information. This module reuses types and logic from
//! the main DHCP module for consistency and maintainability.

pub mod server;

#[cfg(test)]
mod tests;

pub use server::{ProxyConfig, ProxyDhcpServer, spawn_proxy_dhcp_server};
