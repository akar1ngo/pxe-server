//! DHCP Server Implementation
//!
//! This module provides a complete DHCPv4 server implementation for PXE boot environments.
//! It handles DHCP Discover/Offer and Request/Ack exchanges, provides IP address allocation,
//! and includes PXE-specific options.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket as TokioUdpSocket;

use crate::packet::DhcpPacket;
use crate::{DhcpOption, IpPool, MessageType, create_pxe_vendor_options};

/// Configuration for the DHCP server
pub struct DhcpConfig {
    /// Address to bind the DHCP server to
    pub bind: String,

    /// IP address pool start
    pub pool_start: Ipv4Addr,

    /// IP address pool end
    pub pool_end: Ipv4Addr,

    /// Subnet mask to assign to clients
    pub subnet_mask: Ipv4Addr,

    /// Default gateway/router IP
    pub router: Ipv4Addr,

    /// DNS server IP
    pub dns_server: Ipv4Addr,

    /// Domain name to assign
    pub domain_name: Option<String>,

    /// DHCP server identifier (usually the server's IP)
    pub server_identifier: Ipv4Addr,

    /// TFTP server IP for PXE boot
    pub tftp_server: Ipv4Addr,

    /// Boot filename for BIOS clients
    pub bios_bootfile: String,

    /// Boot filename for UEFI clients
    pub efi_bootfile: String,

    /// IP address lease time in seconds
    pub lease_time: u32,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:67".to_string(),
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end: Ipv4Addr::new(192, 168, 1, 200),
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns_server: Ipv4Addr::new(8, 8, 8, 8),
            domain_name: Some("local".to_string()),
            server_identifier: Ipv4Addr::new(192, 168, 1, 1),
            tftp_server: Ipv4Addr::new(192, 168, 1, 1),
            bios_bootfile: "pxelinux.0".to_string(),
            efi_bootfile: "ipxe.efi".to_string(),
            lease_time: 3600, // 1 hour
        }
    }
}

/// DHCP Server state
struct DhcpServerState {
    config: Arc<DhcpConfig>,
    ip_pool: IpPool,
    leases: HashMap<[u8; 6], LeaseInfo>,
}

/// Information about an IP address lease
struct LeaseInfo {
    ip: Ipv4Addr,
    expires_at: Instant,
}

impl DhcpServerState {
    fn new(config: DhcpConfig) -> Self {
        let ip_pool = IpPool::new(config.pool_start, config.pool_end);
        let config = Arc::new(config);

        Self {
            config,
            ip_pool,
            leases: HashMap::new(),
        }
    }

    /// Clean up expired leases
    fn cleanup_expired_leases(&mut self) {
        let now = std::time::Instant::now();
        let expired_macs: Vec<[u8; 6]> = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.expires_at <= now)
            .map(|(&mac, _)| mac)
            .collect();

        for mac in expired_macs {
            self.leases.remove(&mac);
            self.ip_pool.release(mac);
        }
    }

    /// Allocate an IP address for a MAC address
    fn allocate_ip(&mut self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        self.cleanup_expired_leases();

        // Check if we already have a valid lease
        if let Some(lease) = self.leases.get(&mac)
            && lease.expires_at > std::time::Instant::now()
        {
            return Some(lease.ip);
        }

        // Allocate new IP
        if let Some(ip) = self.ip_pool.allocate(mac) {
            let lease = LeaseInfo {
                ip,
                expires_at: std::time::Instant::now() + Duration::from_secs(self.config.lease_time as u64),
            };
            self.leases.insert(mac, lease);
            Some(ip)
        } else {
            None
        }
    }
}

/// Main DHCP server
pub struct DhcpServer {
    state: Arc<Mutex<DhcpServerState>>,
    send_socket: Option<Arc<TokioUdpSocket>>,
}

impl DhcpServer {
    /// Create a new DHCP server with the given configuration
    pub fn new(config: DhcpConfig) -> Self {
        let send_socket = Self::create_send_socket(&config).ok().map(Arc::new);
        let state = Arc::new(Mutex::new(DhcpServerState::new(config)));
        Self { state, send_socket }
    }

    /// Create a new DHCP server for testing (without creating sockets)
    #[cfg(test)]
    pub fn new_for_test(config: DhcpConfig) -> Self {
        let state = Arc::new(Mutex::new(DhcpServerState::new(config)));
        Self {
            state,
            send_socket: None,
        }
    }

    /// Create a socket for sending responses on the correct interface
    fn create_send_socket(config: &DhcpConfig) -> Result<TokioUdpSocket> {
        use std::net::UdpSocket;

        use socket2::{Domain, Protocol, Socket, Type};

        // Create socket with socket2 for better control
        let socket2 =
            Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("Failed to create send socket")?;

        // Enable broadcast
        socket2
            .set_broadcast(true)
            .context("Failed to enable broadcast on send socket")?;

        // Set socket to non-blocking mode
        socket2
            .set_nonblocking(true)
            .context("Failed to set send socket to non-blocking mode")?;

        // Bind to the server's IP address with any port for sending
        let server_ip = config.server_identifier;
        let bind_addr = std::net::SocketAddr::new(server_ip.into(), 67);
        socket2.set_reuse_address(true)?;
        socket2.set_reuse_port(true)?;

        socket2
            .bind(&bind_addr.into())
            .with_context(|| format!("Failed to bind send socket to {}", bind_addr))?;

        // Convert to std::net::UdpSocket and then to Tokio
        let std_socket: UdpSocket = socket2.into();
        let tokio_socket = TokioUdpSocket::from_std(std_socket).context("Failed to convert send socket to Tokio")?;

        tracing::info!("Created DHCP send socket bound to {}", server_ip);
        Ok(tokio_socket)
    }

    /// Run the DHCP server
    pub async fn run(&self) -> Result<()> {
        let bind_addr = {
            let state = self.state.lock().unwrap();
            state.config.bind.clone()
        };

        tracing::info!("Starting DHCP server on {}", bind_addr);

        // Create socket with socket2 for better control
        let socket2 = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("Failed to create socket")?;

        // Enable broadcast reception
        socket2
            .set_broadcast(true)
            .context("Failed to enable broadcast on DHCP socket")?;

        // Enable address reuse to properly receive broadcasts
        socket2
            .set_reuse_address(true)
            .context("Failed to set SO_REUSEADDR on DHCP socket")?;

        // On systems that support it, enable SO_REUSEPORT for better broadcast reception
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            if let Err(e) = socket2.set_reuse_port(true) {
                tracing::warn!("Failed to set SO_REUSEPORT on DHCP socket: {}", e);
            } else {
                tracing::info!("Successfully set SO_REUSEPORT on DHCP socket");
            }
        }

        // Set socket to non-blocking mode
        socket2
            .set_nonblocking(true)
            .context("Failed to set socket to non-blocking mode")?;

        // For broadcast DHCP reception, always bind to 0.0.0.0:67
        // This ensures we can receive broadcast packets from any interface
        let addr: std::net::SocketAddr = bind_addr
            .parse()
            .with_context(|| format!("Invalid bind address: {}", bind_addr))?;

        let actual_bind_addr = std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), addr.port());

        socket2
            .bind(&actual_bind_addr.into())
            .with_context(|| format!("Failed to bind DHCP server to {}", actual_bind_addr))?;

        tracing::info!(
            "DHCP socket bound to {} for broadcast reception (configured for {})",
            actual_bind_addr,
            addr
        );

        // Convert to std::net::UdpSocket and then to Tokio
        let std_socket: UdpSocket = socket2.into();
        let socket = TokioUdpSocket::from_std(std_socket).context("Failed to convert to Tokio socket")?;

        let mut buffer = [0u8; 1024];

        loop {
            match socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    tracing::info!("Received DHCP packet ({} bytes) from {}", len, addr);
                    let data = &buffer[..len];
                    if let Err(e) = self.handle_packet(data, addr, &socket).await {
                        tracing::warn!("Error handling DHCP packet from {}: {}", addr, e);
                    }
                }
                Err(e) => {
                    tracing::error!("Error receiving DHCP packet: {}", e);
                }
            }
        }
    }

    /// Handle an incoming DHCP packet
    async fn handle_packet(&self, data: &[u8], _addr: SocketAddr, _socket: &TokioUdpSocket) -> Result<()> {
        tracing::info!("Parsing DHCP packet...");
        let packet = DhcpPacket::from_bytes(data).context("Failed to parse DHCP packet")?;

        let message_type = packet.get_message_type().context("DHCP packet missing message type")?;

        tracing::info!(
            "Received DHCP {} from MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, XID: 0x{:08x}",
            format!("{:?}", message_type),
            packet.chaddr[0],
            packet.chaddr[1],
            packet.chaddr[2],
            packet.chaddr[3],
            packet.chaddr[4],
            packet.chaddr[5],
            packet.xid
        );

        match message_type {
            MessageType::Discover => {
                tracing::info!("Processing DHCP Discover");
                if let Some(ref send_socket) = self.send_socket {
                    self.handle_discover(packet, send_socket).await?;
                } else {
                    return Err(anyhow::anyhow!("Send socket not available"));
                }
            }
            MessageType::Request => {
                tracing::info!("Processing DHCP Request");
                if let Some(ref send_socket) = self.send_socket {
                    self.handle_request(packet, send_socket).await?;
                } else {
                    return Err(anyhow::anyhow!("Send socket not available"));
                }
            }
            MessageType::Release => {
                tracing::info!("Processing DHCP Release");
                self.handle_release(packet).await?;
            }
            _ => {
                tracing::debug!("Ignoring DHCP message type: {:?}", message_type);
            }
        }

        Ok(())
    }

    /// Handle DHCP Discover message
    async fn handle_discover(&self, request: DhcpPacket, socket: &TokioUdpSocket) -> Result<()> {
        let mac = request.get_mac_address();

        let (allocated_ip, config) = {
            let mut state = self.state.lock().unwrap();
            let allocated_ip = state.allocate_ip(mac);
            (allocated_ip, state.config.clone())
        };

        if let Some(ip) = allocated_ip {
            let mut offer = request.create_response(MessageType::Offer);
            offer.yiaddr = ip;
            offer.siaddr = config.tftp_server;

            // Add standard DHCP options
            offer.add_ip_option(DhcpOption::SubnetMask as u8, config.subnet_mask);
            offer.add_ip_option(DhcpOption::Router as u8, config.router);
            offer.add_ip_option(DhcpOption::DomainNameServer as u8, config.dns_server);
            offer.add_ip_option(DhcpOption::ServerIdentifier as u8, config.server_identifier);
            offer.add_u32_option(DhcpOption::IpAddressLeaseTime as u8, config.lease_time);

            // Add renewal and rebinding times (T1 and T2)
            let renewal_time = config.lease_time / 2; // T1 = 50% of lease time
            let rebinding_time = (config.lease_time * 7) / 8; // T2 = 87.5% of lease time
            offer.add_u32_option(DhcpOption::RenewalTime as u8, renewal_time);
            offer.add_u32_option(DhcpOption::RebindingTime as u8, rebinding_time);

            if let Some(domain) = &config.domain_name {
                offer.add_string_option(DhcpOption::DomainName as u8, domain);
            }

            // Add PXE vendor-specific options
            let pxe_vendor_options = create_pxe_vendor_options();
            offer.add_option(DhcpOption::VendorSpecificInfo as u8, &pxe_vendor_options);

            // Add PXE options if this is a PXE client
            if request.is_pxe_client() {
                tracing::info!(
                    "Offering IP {} to PXE client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );

                // Determine boot file based on client architecture
                let bootfile = self.determine_bootfile(&request, &config);
                offer.add_string_option(DhcpOption::BootfileName as u8, &bootfile);
                offer.add_string_option(DhcpOption::TftpServerName as u8, &config.tftp_server.to_string());

                // Set legacy fields for compatibility
                if bootfile.len() < 128 {
                    offer.file[..bootfile.len()].copy_from_slice(bootfile.as_bytes());
                }
            } else {
                tracing::info!(
                    "Offering IP {} to regular client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    ip,
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5]
                );
            }

            if let Some(vendor_class) = request.get_option(DhcpOption::VendorClassIdentifier as u8) {
                // echo the client's option 60 back in the offer/ack
                offer.add_option(DhcpOption::VendorClassIdentifier as u8, &vendor_class);
            } else {
                // optional: advertise minimal PXE client id so firmware recognizes the offer
                offer.add_string_option(DhcpOption::VendorClassIdentifier as u8, "PXEClient");
            }

            self.send_response(offer, socket).await?;
        } else {
            tracing::warn!(
                "No IP addresses available for MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        }

        Ok(())
    }

    /// Handle DHCP Request message
    async fn handle_request(&self, request: DhcpPacket, socket: &TokioUdpSocket) -> Result<()> {
        let mac = request.get_mac_address();
        let requested_ip = request.get_requested_ip().or_else(|| {
            if !request.ciaddr.is_unspecified() {
                Some(request.ciaddr)
            } else {
                None
            }
        });

        let server_id = request.get_server_identifier();
        let config = {
            let state = self.state.lock().unwrap();
            state.config.clone()
        };

        // Check if this request is for us
        if let Some(server_id) = server_id
            && server_id != config.server_identifier
        {
            tracing::debug!("DHCP Request for different server: {}", server_id);
            return Ok(());
        }

        if let Some(ip) = requested_ip {
            // Verify the IP is allocated to this MAC
            let is_valid = {
                let mut state = self.state.lock().unwrap();
                state.cleanup_expired_leases();

                if let Some(lease) = state.leases.get(&mac) {
                    lease.ip == ip && lease.expires_at > std::time::Instant::now()
                } else {
                    // Try to allocate the requested IP
                    if let Some(allocated_ip) = state.allocate_ip(mac) {
                        allocated_ip == ip
                    } else {
                        false
                    }
                }
            };

            if is_valid {
                let mut ack = request.create_response(MessageType::Ack);
                ack.yiaddr = ip;
                ack.siaddr = config.tftp_server;

                // Add standard options
                ack.add_ip_option(DhcpOption::SubnetMask as u8, config.subnet_mask);
                ack.add_ip_option(DhcpOption::Router as u8, config.router);
                ack.add_ip_option(DhcpOption::DomainNameServer as u8, config.dns_server);
                ack.add_ip_option(DhcpOption::ServerIdentifier as u8, config.server_identifier);
                ack.add_u32_option(DhcpOption::IpAddressLeaseTime as u8, config.lease_time);

                // Add renewal and rebinding times (T1 and T2)
                let renewal_time = config.lease_time / 2; // T1 = 50% of lease time
                let rebinding_time = (config.lease_time * 7) / 8; // T2 = 87.5% of lease time
                ack.add_u32_option(DhcpOption::RenewalTime as u8, renewal_time);
                ack.add_u32_option(DhcpOption::RebindingTime as u8, rebinding_time);

                if let Some(domain) = &config.domain_name {
                    ack.add_string_option(DhcpOption::DomainName as u8, domain);
                }

                // Add PXE vendor-specific options
                let pxe_vendor_options = create_pxe_vendor_options();
                ack.add_option(DhcpOption::VendorSpecificInfo as u8, &pxe_vendor_options);

                // Add PXE options if this is a PXE client
                if request.is_pxe_client() {
                    tracing::info!(
                        "ACK IP {} to PXE client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip,
                        mac[0],
                        mac[1],
                        mac[2],
                        mac[3],
                        mac[4],
                        mac[5]
                    );

                    let bootfile = self.determine_bootfile(&request, &config);
                    ack.add_string_option(DhcpOption::BootfileName as u8, &bootfile);
                    ack.add_string_option(DhcpOption::TftpServerName as u8, &config.tftp_server.to_string());

                    // Set legacy fields
                    if bootfile.len() < 128 {
                        ack.file[..bootfile.len()].copy_from_slice(bootfile.as_bytes());
                    }
                } else {
                    tracing::info!(
                        "ACK IP {} to regular client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        ip,
                        mac[0],
                        mac[1],
                        mac[2],
                        mac[3],
                        mac[4],
                        mac[5]
                    );
                }

                if let Some(vendor_class) = request.get_option(DhcpOption::VendorClassIdentifier as u8) {
                    // echo the client's option 60 back in the offer/ack
                    ack.add_option(DhcpOption::VendorClassIdentifier as u8, &vendor_class);
                } else {
                    // optional: advertise minimal PXE client id so firmware recognizes the offer
                    ack.add_string_option(DhcpOption::VendorClassIdentifier as u8, "PXEClient");
                }

                self.send_response(ack, socket).await?;
            } else {
                // Send NAK
                let mut nak = request.create_response(MessageType::Nak);
                nak.add_ip_option(DhcpOption::ServerIdentifier as u8, config.server_identifier);

                tracing::warn!(
                    "NAK to client {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} - invalid IP request: {}",
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5],
                    ip
                );

                self.send_response(nak, socket).await?;
            }
        } else {
            tracing::warn!(
                "DHCP Request without requested IP from {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
        }

        Ok(())
    }

    /// Handle DHCP Release message
    async fn handle_release(&self, request: DhcpPacket) -> Result<()> {
        let mac = request.get_mac_address();

        {
            let mut state = self.state.lock().unwrap();
            state.leases.remove(&mac);
            state.ip_pool.release(mac);
        }

        tracing::info!(
            "Released lease for MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );

        Ok(())
    }

    /// Determine the appropriate boot file for a PXE client
    fn determine_bootfile(&self, request: &DhcpPacket, config: &DhcpConfig) -> String {
        // Try to determine client architecture from vendor class identifier
        if let Some(vendor_class) = request.get_option(DhcpOption::VendorClassIdentifier as u8) {
            let vendor_str = String::from_utf8_lossy(&vendor_class);

            // Parse architecture from PXEClient string
            // Format: PXEClient:Arch:XXXXX:UNDI:YYYYYY
            if vendor_str.contains(":Arch:00007:") || vendor_str.contains(":Arch:00009:") {
                // UEFI x64 or EFI BC
                return config.efi_bootfile.clone();
            }
        }

        // Default to BIOS boot file
        config.bios_bootfile.clone()
    }

    /// Send a DHCP response packet
    async fn send_response(&self, packet: DhcpPacket, socket: &TokioUdpSocket) -> Result<()> {
        let data = packet.to_bytes();

        // Determine destination address
        let dest_addr = if packet.flags & 0x8000 != 0 || packet.giaddr.is_unspecified() {
            // Broadcast flag set or no relay agent
            SocketAddr::from(([255, 255, 255, 255], 68))
        } else {
            // Send via relay agent
            SocketAddr::from((packet.giaddr.octets(), 67))
        };

        tracing::info!("Sending DHCP response ({} bytes) to {}", data.len(), dest_addr);

        socket
            .send_to(&data, dest_addr)
            .await
            .with_context(|| format!("Failed to send DHCP response to {}", dest_addr))?;

        tracing::info!("Successfully sent DHCP response to {}", dest_addr);
        Ok(())
    }
}

/// Spawn a DHCP server task
pub async fn spawn_dhcp_server(config: DhcpConfig) -> Result<()> {
    let server = DhcpServer::new(config);
    server.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_config_default() {
        let config = DhcpConfig::default();
        assert_eq!(config.bind, "0.0.0.0:67");
        assert_eq!(config.lease_time, 3600);
    }

    #[test]
    fn test_dhcp_server_creation() {
        let config = DhcpConfig {
            bind: "127.0.0.1:0".to_string(),
            server_identifier: Ipv4Addr::new(127, 0, 0, 1),
            tftp_server: Ipv4Addr::new(127, 0, 0, 1),
            router: Ipv4Addr::new(127, 0, 0, 1),
            pool_start: Ipv4Addr::new(127, 0, 1, 100),
            pool_end: Ipv4Addr::new(127, 0, 1, 200),
            ..Default::default()
        };
        let _server = DhcpServer::new_for_test(config);
    }

    #[test]
    fn test_dhcp_state() {
        let config = DhcpConfig {
            server_identifier: Ipv4Addr::new(127, 0, 0, 1),
            tftp_server: Ipv4Addr::new(127, 0, 0, 1),
            router: Ipv4Addr::new(127, 0, 0, 1),
            pool_start: Ipv4Addr::new(127, 0, 1, 100),
            pool_end: Ipv4Addr::new(127, 0, 1, 200),
            ..Default::default()
        };
        let mut state = DhcpServerState::new(config);

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let ip = state.allocate_ip(mac);
        assert!(ip.is_some());

        // Same MAC should get same IP
        let ip2 = state.allocate_ip(mac);
        assert_eq!(ip, ip2);
    }
}
