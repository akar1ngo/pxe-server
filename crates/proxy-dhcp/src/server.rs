//! Proxy DHCP Server Implementation
//!
//! This module provides a Proxy DHCP server that works alongside existing DHCP servers
//! to provide PXE boot information. It reuses types and logic from the main DHCP module
//! for consistency and maintainability.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::sync::Arc;

use anyhow::{Context, Result};
use dhcp::packet::DhcpPacket;
use dhcp::{DhcpOption, MessageType, OpCode};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Configuration for the Proxy DHCP server
pub struct ProxyConfig {
    /// Bind address (default "0.0.0.0:4011")
    pub bind: String,
    /// IP address of the TFTP server to advertise
    pub tftp_server: Ipv4Addr,
    /// Boot file for legacy/BIOS PXE clients
    pub bios_bootfile: String,
    /// Boot file for UEFI PXE clients
    pub efi_bootfile: String,
    /// Optionally override the server identifier option (option 54)
    /// If None, tftp_server is used
    pub server_identifier: Option<Ipv4Addr>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:4011".to_string(),
            tftp_server: Ipv4Addr::new(192, 168, 1, 1),
            bios_bootfile: "pxelinux.0".to_string(),
            efi_bootfile: "ipxe.efi".to_string(),
            server_identifier: None,
        }
    }
}

/// Proxy DHCP Server
pub struct ProxyDhcpServer {
    config: Arc<ProxyConfig>,
    socket_67: UdpSocket,
    socket_4011: Option<UdpSocket>,
}

impl ProxyDhcpServer {
    /// Create a new Proxy DHCP server with the given configuration
    pub async fn new(config: ProxyConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Create socket for port 67 (standard DHCP port) - REQUIRED for proxy DHCP responses
        let socket_67 = Self::create_socket_67().await?;

        // Try to create socket for port 4011 (for directed PXE requests)
        let socket_4011 = Self::create_socket_4011(&config.bind).await.ok();

        if socket_4011.is_some() {
            info!("Proxy DHCP server listening on both port 67 and 4011");
        } else {
            info!("Proxy DHCP server listening on port 67 only (port 4011 unavailable)");
        }

        Ok(Self {
            config,
            socket_67,
            socket_4011,
        })
    }

    /// Create and configure the socket for port 4011 (optional)
    async fn create_socket_4011(bind_addr: &str) -> Result<UdpSocket> {
        let std_socket = StdUdpSocket::bind(bind_addr).with_context(|| format!("Failed to bind to {}", bind_addr))?;
        std_socket.set_broadcast(true)?;
        std_socket.set_nonblocking(true)?;

        let tokio_socket = UdpSocket::from_std(std_socket)?;

        debug!(
            "Created socket for port 4011, local addr: {:?}",
            tokio_socket.local_addr()?
        );

        Ok(tokio_socket)
    }

    /// Create and configure the socket for port 67 - REQUIRED for proxy DHCP responses
    async fn create_socket_67() -> Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .context("Failed to create socket for port 67")?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;

        let bind_addr = SocketAddr::new("0.0.0.0".parse()?, 67);
        socket
            .bind(&bind_addr.into())
            .context("Failed to bind to port 67 - proxy DHCP requires port 67 access")?;

        let std_socket: StdUdpSocket = socket.into();
        let tokio_socket = UdpSocket::from_std(std_socket)?;

        debug!(
            "Created socket for port 67, local addr: {:?}",
            tokio_socket.local_addr()?
        );

        Ok(tokio_socket)
    }

    /// Run the proxy DHCP server
    pub async fn run(&mut self) -> Result<()> {
        info!(
            "Starting Proxy DHCP server on port 67 (advertising TFTP {})",
            self.config.tftp_server
        );

        let mut buf_67 = vec![0u8; 1500];
        let mut buf_4011 = vec![0u8; 1500];

        loop {
            tokio::select! {
                biased;

                // For listening to general DHCP requests.
                res = self.socket_67.recv_from(&mut buf_67) => {
                    match res {
                        Ok((len, src)) => {
                            // Send responses from port 67 for DISCOVER/OFFER exchange
                            if let Err(e) = self.handle_packet(&buf_67[..len], src, &self.socket_67).await {
                                warn!("Failed to handle packet from {} on port 67: {}", src, e);
                            }
                        }
                        Err(e) => warn!("Error receiving on port 67: {}", e),
                    }
                },

                // For listening to directed, boot-related requests.
                res = async {
                    if let Some(ref socket) = self.socket_4011 {
                        socket.recv_from(&mut buf_4011).await
                    } else {
                        // If no socket_4011, wait forever
                        std::future::pending().await
                    }
                } => {
                    match res {
                        Ok((len, src)) => {
                            // Send responses from port 4011 for directed requests
                            if let Err(e) = self.handle_packet(&buf_4011[..len], src, self.socket_4011.as_ref().unwrap()).await {
                                warn!("Failed to handle packet from {src} on port 4011: {e}");
                            }
                        }
                        Err(e) => warn!("Error receiving on port 4011: {e}"),
                    }
                }
            }
        }
    }

    async fn handle_packet(&self, data: &[u8], src: SocketAddr, send_socket: &UdpSocket) -> Result<()> {
        let request = match DhcpPacket::from_bytes(data) {
            Ok(packet) => packet,
            Err(_) => {
                debug!("Ignoring non-DHCP packet from {}", src);
                return Ok(());
            }
        };

        if request.op != OpCode::BootRequest {
            debug!("Ignoring non-BOOT-REQUEST from {}", src);
            return Ok(());
        }

        if !self.validate_pxe_request(&request) {
            debug!("Ignoring invalid PXE request from {}", src);
            return Ok(());
        }

        let message_type = request.get_message_type();
        match message_type {
            Some(MessageType::Discover) => {
                // Only respond to DISCOVER messages as proxy DHCP. Let the regular DHCP server
                // handle IP allocation.
                self.handle_discover(&request, src, send_socket).await?;
            }
            Some(MessageType::Request) => {
                // Only handle REQUEST if it's specifically for our server ID.
                if let Some(recipient) = request.get_server_identifier() {
                    let ourselves = self.config.server_identifier.unwrap_or(self.config.tftp_server);
                    if recipient == ourselves {
                        self.handle_request(&request, src, send_socket).await?;
                    } else {
                        debug!("REQUEST for different server {recipient} (we are {ourselves})");
                    }
                } else {
                    debug!("REQUEST without server ID, ignoring (let DHCP server handle)");
                }
            }
            _ => {
                debug!("Ignoring DHCP message type {message_type:?} from {src}");
            }
        }

        Ok(())
    }

    async fn handle_discover(&self, request: &DhcpPacket, src: SocketAddr, send_socket: &UdpSocket) -> Result<()> {
        let bootfile = self.determine_bootfile(request);

        info!(
            "PXE DISCOVER xid={:#x} from {} -> offering '{}'",
            request.xid, src, bootfile
        );

        let response = self.create_offer(request, &bootfile)?;
        self.send_response(&response, request, src, send_socket).await?;

        Ok(())
    }

    async fn handle_request(&self, request: &DhcpPacket, src: SocketAddr, send_socket: &UdpSocket) -> Result<()> {
        let bootfile = self.determine_bootfile(request);

        info!("PXE REQUEST xid={:#x} from {} -> ACK '{}'", request.xid, src, bootfile);

        let response = self.create_ack(request, &bootfile)?;
        self.send_response(&response, request, src, send_socket).await?;

        Ok(())
    }

    fn validate_pxe_request(&self, request: &DhcpPacket) -> bool {
        // Vendor Class Identifier; must be present and start with "PXEClient"
        let vendor_class_data = match request.get_option(DhcpOption::VendorClassIdentifier as u8) {
            Some(data) => data,
            None => {
                debug!("Missing option 60 (Vendor Class Identifier)");
                return false;
            }
        };

        let vendor_class = String::from_utf8_lossy(&vendor_class_data);
        if !vendor_class.starts_with("PXEClient") && !vendor_class.starts_with("HTTPClient") {
            debug!("Invalid option 60 format: {}", vendor_class);
            return false;
        }

        // Client System Architecture Type, RFC 4578
        if request.get_option(93).is_none() {
            debug!("Missing option 93 (Client System Architecture Type)");
            return false;
        }

        // Client Network Interface Identifier, RFC 4578
        if request.get_option(94).is_none() {
            debug!("Missing option 94 (Client Network Interface Identifier)");
            return false;
        }

        // Client Machine Identifier, RFC 4578
        if let Some(guid) = request.get_option(97) {
            match guid.len() {
                // some firmware omit the field.
                0 => {}

                // if provided, validate.
                17 => {
                    if guid[0] != 0 {
                        debug!("Invalid option 97: `t` octet must be 0");
                        return false;
                    }
                }

                // clearly violating the spec
                _ => {
                    debug!("Invalid option 97 length: {} (should be 0 or 17)", guid.len());
                    return false;
                }
            }
        }

        true
    }

    /// Determine the appropriate boot file for the client
    pub fn determine_bootfile(&self, request: &DhcpPacket) -> String {
        if let Some(vendor_class_data) = request.get_option(DhcpOption::VendorClassIdentifier as u8) {
            let vendor_class = String::from_utf8_lossy(&vendor_class_data);

            // Check for UEFI indicators
            if vendor_class.to_uppercase().contains("EFI") ||
               vendor_class.contains("Arch:00007") ||  // EFI x64
               vendor_class.contains("Arch:00009")
            // EFI x64 alternative
            {
                return self.config.efi_bootfile.clone();
            }
        }

        // Default to BIOS boot file
        self.config.bios_bootfile.clone()
    }

    /// Create a DHCP Offer response
    pub fn create_offer(&self, request: &DhcpPacket, bootfile: &str) -> Result<DhcpPacket> {
        let mut response = request.create_response(MessageType::Offer);
        self.populate_response(&mut response, request, bootfile)?;
        Ok(response)
    }

    /// Create a DHCP Ack response
    pub fn create_ack(&self, request: &DhcpPacket, bootfile: &str) -> Result<DhcpPacket> {
        let mut response = request.create_response(MessageType::Ack);
        self.populate_response(&mut response, request, bootfile)?;
        Ok(response)
    }

    fn populate_response(&self, response: &mut DhcpPacket, request: &DhcpPacket, bootfile: &str) -> Result<()> {
        // Must set to zero (cf. PXE Specification v2.1, section 2.4.3)
        response.ciaddr = Ipv4Addr::UNSPECIFIED;
        // TianoCore identifies proxy offers by checking this field is zero (cf. PxeBcParseDhcp4Packet)
        response.yiaddr = Ipv4Addr::UNSPECIFIED;

        // EFI implementations (like TianoCore) will prioritize this field over option 54.
        // cf. UEFI Specification v2.11, section E.4.20.2
        response.siaddr = self.config.tftp_server;

        // ...
        response.giaddr = request.giaddr;
        response.flags = request.flags;

        // Set boot filename in the file field (up to 128 bytes)
        let bootfile_bytes = bootfile.as_bytes();
        let copy_len = std::cmp::min(bootfile_bytes.len(), 128);
        response.file[..copy_len].copy_from_slice(&bootfile_bytes[..copy_len]);

        let server_id = self.config.server_identifier.unwrap_or(self.config.tftp_server);
        response.add_ip_option(DhcpOption::ServerIdentifier as u8, server_id);

        if let Some(vendor_class_data) = request.get_option(DhcpOption::VendorClassIdentifier as u8) {
            response.add_option(DhcpOption::VendorClassIdentifier as u8, &vendor_class_data);
        } else {
            response.add_string_option(DhcpOption::VendorClassIdentifier as u8, "PXEClient");
        }

        response.add_string_option(DhcpOption::TftpServerName as u8, &self.config.tftp_server.to_string());
        response.add_string_option(DhcpOption::BootfileName as u8, bootfile);

        // Required by RFC 4578
        if let Some(guid) = request.get_option(97) {
            response.add_option(97, &guid);
        }

        // Add PXE vendor-specific options (option 43)
        let pxe_options = [
            6, // Option code
            1, // Length
            8, // Bit 3: Download boot file without user prompt
        ];

        response.add_option(DhcpOption::VendorSpecificInfo as u8, &pxe_options);

        Ok(())
    }

    async fn send_response(
        &self,
        response: &DhcpPacket,
        request: &DhcpPacket,
        src: SocketAddr,
        send_socket: &UdpSocket,
    ) -> Result<()> {
        let response_bytes = response.to_bytes();

        // Determine destination address
        let dest = self.determine_destination(request, src);

        // Debug logging to show response details
        debug!("Proxy DHCP response details:");
        debug!("  siaddr: {}", response.siaddr);
        debug!("  yiaddr: {}", response.yiaddr);
        debug!("  ciaddr: {}", response.ciaddr);

        // Log file field content
        let file_str = std::str::from_utf8(&response.file).unwrap_or("<invalid>");
        let file_end = file_str.find('\0').unwrap_or(file_str.len());
        debug!("  file field: '{}'", &file_str[..file_end]);

        // Log key DHCP options
        if let Some(server_id) = response.get_server_identifier() {
            debug!("  Server ID (54): {}", server_id);
        }
        if let Some(vendor_class) = response.get_option(DhcpOption::VendorClassIdentifier as u8) {
            debug!("  Vendor Class (60): '{}'", String::from_utf8_lossy(&vendor_class));
        }
        if let Some(tftp_server) = response.get_option(DhcpOption::TftpServerName as u8) {
            debug!("  TFTP Server (66): '{}'", String::from_utf8_lossy(&tftp_server));
        }
        if let Some(bootfile) = response.get_option(DhcpOption::BootfileName as u8) {
            debug!("  Bootfile (67): '{}'", String::from_utf8_lossy(&bootfile));
        }

        // Log detailed send information
        debug!(
            "Sending {} bytes to {} via socket {:?}",
            response_bytes.len(),
            dest,
            send_socket.local_addr()?
        );
        debug!(
            "Response packet dump (first 100 bytes): {:02x?}",
            &response_bytes[..std::cmp::min(100, response_bytes.len())]
        );

        let bytes_sent = send_socket
            .send_to(&response_bytes, dest)
            .await
            .with_context(|| format!("Failed to send response to {}", dest))?;

        debug!("Successfully sent {} bytes to {}", bytes_sent, dest);

        let response_type = match response.get_message_type() {
            Some(MessageType::Offer) => "OFFER",
            Some(MessageType::Ack) => "ACK",
            _ => "RESPONSE",
        };

        info!("Sent Proxy DHCP{} to {}", response_type, dest);
        Ok(())
    }

    /// Determine where to send the response
    pub fn determine_destination(&self, request: &DhcpPacket, src: SocketAddr) -> SocketAddr {
        // Check if broadcast flag is set
        let broadcast_flag = (request.flags & 0x8000) != 0;

        // If source IP is unspecified or broadcast flag is set, use broadcast
        let src_v4 = match src {
            SocketAddr::V4(v4) => *v4.ip(),
            SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };

        if src_v4.is_unspecified() || broadcast_flag {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68))
        } else {
            SocketAddr::V4(SocketAddrV4::new(src_v4, 68))
        }
    }
}

/// Spawn a proxy DHCP server task
pub async fn spawn_proxy_dhcp_server(config: ProxyConfig) -> Result<()> {
    let mut server = ProxyDhcpServer::new(config).await?;
    server.run().await
}

#[cfg(test)]
pub mod tests {
    use dhcp::{DhcpOption, HardwareType, MessageType, OpCode};

    use super::*;

    /// Create a mock ProxyDhcpServer for testing (without actual sockets)
    pub fn create_test_server(config: ProxyConfig) -> ProxyDhcpServer {
        // Create dummy sockets for testing - we'll use loopback sockets that won't actually be used
        let std_socket_67 = std::net::UdpSocket::bind("127.0.0.1:0").expect("Failed to create test socket");
        std_socket_67.set_nonblocking(true).expect("Failed to set nonblocking");
        let tokio_socket_67 = UdpSocket::from_std(std_socket_67).expect("Failed to convert to tokio socket");

        ProxyDhcpServer {
            config: Arc::new(config),
            socket_67: tokio_socket_67,
            socket_4011: None, // Don't create socket_4011 for tests
        }
    }

    fn create_test_request() -> DhcpPacket {
        let mut packet = DhcpPacket::new();
        packet.op = OpCode::BootRequest;
        packet.htype = HardwareType::Ethernet;
        packet.hlen = 6;
        packet.xid = 0x12345678;
        packet.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Add message type
        packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

        // Add PXE vendor class identifier
        packet.add_string_option(
            DhcpOption::VendorClassIdentifier as u8,
            "PXEClient:Arch:00000:UNDI:002001",
        );

        packet
    }

    #[test]
    fn test_proxy_config_default() {
        let config = ProxyConfig::default();
        assert_eq!(config.bind, "0.0.0.0:4011");
        assert_eq!(config.tftp_server, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(config.bios_bootfile, "pxelinux.0");
        assert_eq!(config.efi_bootfile, "ipxe.efi");
        assert_eq!(config.server_identifier, None);
    }

    #[tokio::test]
    async fn test_determine_bootfile_bios() {
        let config = ProxyConfig::default();
        let server = create_test_server(config);

        let mut request = create_test_request();
        request.add_string_option(
            DhcpOption::VendorClassIdentifier as u8,
            "PXEClient:Arch:00000:UNDI:002001",
        );

        let bootfile = server.determine_bootfile(&request);
        assert_eq!(bootfile, "pxelinux.0");
    }

    #[tokio::test]
    async fn test_determine_bootfile_uefi() {
        let config = ProxyConfig::default();
        let server = create_test_server(config);

        let mut request = DhcpPacket::new();
        request.op = OpCode::BootRequest;
        request.htype = HardwareType::Ethernet;
        request.hlen = 6;
        request.xid = 0x12345678;
        request.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Add message type
        request.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

        // Add PXE vendor class identifier for UEFI
        request.add_string_option(
            DhcpOption::VendorClassIdentifier as u8,
            "PXEClient:Arch:00007:UNDI:003001", // EFI x64
        );

        let bootfile = server.determine_bootfile(&request);
        assert_eq!(bootfile, "ipxe.efi");
    }

    #[tokio::test]
    async fn test_create_offer() {
        let config = ProxyConfig {
            tftp_server: Ipv4Addr::new(192, 168, 1, 10),
            bios_bootfile: "test.0".to_string(),
            ..Default::default()
        };

        let server = create_test_server(config);

        let request = create_test_request();
        let response = server.create_offer(&request, "test.0").unwrap();

        assert_eq!(response.op, OpCode::BootReply);
        assert_eq!(response.xid, request.xid);
        assert_eq!(response.get_mac_address(), request.get_mac_address());
        assert_eq!(response.get_message_type().unwrap(), MessageType::Offer);

        // Verify TFTP server is set
        assert_eq!(response.siaddr, Ipv4Addr::new(192, 168, 1, 10));

        // Verify server identifier option
        assert_eq!(
            response.get_server_identifier().unwrap(),
            Ipv4Addr::new(192, 168, 1, 10)
        );
    }

    #[tokio::test]
    async fn test_determine_destination_unicast() {
        let config = ProxyConfig::default();
        let server = create_test_server(config);

        let mut request = create_test_request();
        request.flags = 0; // No broadcast flag

        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 68));
        let dest = server.determine_destination(&request, src);

        assert_eq!(
            dest,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 68))
        );
    }

    #[tokio::test]
    async fn test_determine_destination_broadcast() {
        let config = ProxyConfig::default();
        let server = create_test_server(config);

        let mut request = create_test_request();
        request.flags = 0x8000; // Broadcast flag set

        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 68));
        let dest = server.determine_destination(&request, src);

        assert_eq!(dest, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)));
    }
}
