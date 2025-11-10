//! DHCP Server Module
//!
//! Implements a minimal DHCPv4 server for PXE boot environments.
//! This server provides basic DHCP functionality including IP address allocation
//! and PXE-specific options for network booting.

pub mod packet;
pub mod server;

#[cfg(test)]
mod tests;

use std::net::Ipv4Addr;

pub use server::{DhcpConfig, DhcpServer, spawn_dhcp_server};

/// DHCP message types as defined in RFC 2131
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Discover),
            2 => Ok(MessageType::Offer),
            3 => Ok(MessageType::Request),
            4 => Ok(MessageType::Decline),
            5 => Ok(MessageType::Ack),
            6 => Ok(MessageType::Nak),
            7 => Ok(MessageType::Release),
            8 => Ok(MessageType::Inform),
            _ => Err(anyhow::anyhow!("Unknown DHCP message type: {}", value)),
        }
    }
}

/// DHCP options as defined in RFC 2132
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    DomainName = 15,
    BroadcastAddress = 28,
    RequestedIpAddress = 50,
    IpAddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    RenewalTime = 58,
    RebindingTime = 59,
    VendorClassIdentifier = 60,
    ClientIdentifier = 61,

    // PXE-specific options
    TftpServerName = 66,
    BootfileName = 67,

    // PXE vendor-specific options
    VendorSpecificInfo = 43,

    End = 255,
}

/// Hardware address types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareType {
    Ethernet = 1,
}

/// DHCP packet operation codes
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    BootRequest = 1,
    BootReply = 2,
}

/// A simple IP address pool for DHCP allocation
#[derive(Debug, Clone)]
pub struct IpPool {
    start: Ipv4Addr,
    end: Ipv4Addr,
    allocated: std::collections::HashMap<[u8; 6], Ipv4Addr>, // MAC -> IP mapping
}

impl IpPool {
    /// Create a new IP pool with the given range
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self {
            start,
            end,
            allocated: std::collections::HashMap::new(),
        }
    }

    /// Allocate an IP address for the given MAC address
    pub fn allocate(&mut self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        // Check if this MAC already has an allocation
        if let Some(&ip) = self.allocated.get(&mac) {
            return Some(ip);
        }

        // Find next available IP
        let start_u32 = u32::from(self.start);
        let end_u32 = u32::from(self.end);

        for ip_u32 in start_u32..=end_u32 {
            let ip = Ipv4Addr::from(ip_u32);
            if !self.allocated.values().any(|&allocated_ip| allocated_ip == ip) {
                self.allocated.insert(mac, ip);
                return Some(ip);
            }
        }

        None
    }

    /// Release an IP address allocation
    pub fn release(&mut self, mac: [u8; 6]) {
        self.allocated.remove(&mac);
    }

    /// Get the current allocation for a MAC address
    pub fn get_allocation(&self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        self.allocated.get(&mac).copied()
    }
}

/// PXE vendor-specific option codes (sub-options within option 43)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PxeVendorOption {
    PxeDiscoveryControl = 6,
    PxeBootServers = 8,
    PxeBootMenu = 9,
    PxeMenuPrompt = 10,
}

/// Create PXE vendor-specific option 43 data
#[allow(clippy::vec_init_then_push)]
pub fn create_pxe_vendor_options() -> Vec<u8> {
    let mut options = Vec::new();

    // PXE Discovery Control (option 6)
    // Bit 0: Disable broadcast discovery
    // Bit 1: Disable multicast discovery
    // Bit 2: Use only boot servers from option 8
    // Bit 3: Download boot file without user prompt
    options.push(PxeVendorOption::PxeDiscoveryControl as u8);
    options.push(1); // length
    options.push(0x08); // Bit 3 set: Download boot file without user prompt

    // PXE Boot Menu (option 9) - Empty to indicate no menu
    options.push(PxeVendorOption::PxeBootMenu as u8);
    options.push(0); // length 0 = no menu

    // End of vendor options
    options.push(255);

    options
}
