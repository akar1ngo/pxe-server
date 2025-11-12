//! DHCP Packet handling
//!
//! This module provides functionality for parsing and creating DHCP packets
//! according to RFC 2131 and RFC 2132.

use std::net::Ipv4Addr;

use crate::{DhcpOption, HardwareType, MessageType, OpCode};

/// DHCP packet structure as defined in RFC 2131
pub struct DhcpPacket {
    pub op: OpCode,
    pub htype: HardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr, // client IP address from client
    pub yiaddr: Ipv4Addr, // client IP address from server
    pub siaddr: Ipv4Addr, // server IP address
    pub giaddr: Ipv4Addr, // gateway IP address
    pub chaddr: [u8; 16], // client hardware address
    pub sname: [u8; 64],  // server host name
    pub file: [u8; 128],  // boot file name
    pub options: Vec<u8>,
}

impl DhcpPacket {
    /// Create a new DHCP packet
    pub fn new() -> Self {
        Self {
            op: OpCode::BootRequest,
            htype: HardwareType::Ethernet,
            hlen: 6,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0; 16],
            sname: [0; 64],
            file: [0; 128],
            options: Vec::new(),
        }
    }

    /// Parse a DHCP packet from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, anyhow::Error> {
        if data.len() < 236 {
            return Err(anyhow::anyhow!("DHCP packet too short"));
        }

        let op = match data[0] {
            1 => OpCode::BootRequest,
            2 => OpCode::BootReply,
            _ => return Err(anyhow::anyhow!("Invalid op code: {}", data[0])),
        };

        let htype = match data[1] {
            1 => HardwareType::Ethernet,
            _ => return Err(anyhow::anyhow!("Unsupported hardware type: {}", data[1])),
        };

        let hlen = data[2];
        let hops = data[3];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let secs = u16::from_be_bytes([data[8], data[9]]);
        let flags = u16::from_be_bytes([data[10], data[11]]);

        let ciaddr = Ipv4Addr::from([data[12], data[13], data[14], data[15]]);
        let yiaddr = Ipv4Addr::from([data[16], data[17], data[18], data[19]]);
        let siaddr = Ipv4Addr::from([data[20], data[21], data[22], data[23]]);
        let giaddr = Ipv4Addr::from([data[24], data[25], data[26], data[27]]);

        let mut chaddr = [0; 16];
        chaddr.copy_from_slice(&data[28..44]);

        let mut sname = [0; 64];
        sname.copy_from_slice(&data[44..108]);

        let mut file = [0; 128];
        file.copy_from_slice(&data[108..236]);

        // Parse options
        let mut options = Vec::new();
        if data.len() > 236 {
            // Check for magic cookie (0x63825363)
            if data.len() >= 240 && data[236..240] == [0x63, 0x82, 0x53, 0x63] {
                options = data[240..].to_vec();
            }
        }

        Ok(DhcpPacket {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Convert the packet to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(576); // Minimum DHCP packet size

        packet.push(self.op as u8);
        packet.push(self.htype as u8);
        packet.push(self.hlen);
        packet.push(self.hops);
        packet.extend_from_slice(&self.xid.to_be_bytes());
        packet.extend_from_slice(&self.secs.to_be_bytes());
        packet.extend_from_slice(&self.flags.to_be_bytes());
        packet.extend_from_slice(&self.ciaddr.octets());
        packet.extend_from_slice(&self.yiaddr.octets());
        packet.extend_from_slice(&self.siaddr.octets());
        packet.extend_from_slice(&self.giaddr.octets());
        packet.extend_from_slice(&self.chaddr);
        packet.extend_from_slice(&self.sname);
        packet.extend_from_slice(&self.file);

        // Add magic cookie
        packet.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // Add options
        packet.extend_from_slice(&self.options);

        // Pad to minimum size if needed
        while packet.len() < 300 {
            packet.push(0);
        }

        packet
    }

    /// Get the client's MAC address
    pub fn get_mac_address(&self) -> [u8; 6] {
        let mut mac = [0; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    /// Set the client's MAC address
    pub fn set_mac_address(&mut self, mac: [u8; 6]) {
        self.chaddr[..6].copy_from_slice(&mac);
    }

    /// Get an option from the packet
    pub fn get_option(&self, option_code: u8) -> Option<Vec<u8>> {
        let mut i = 0;
        while i < self.options.len() {
            let code = self.options[i];
            if code == 255 {
                // End option
                break;
            }
            if code == 0 {
                // Pad option
                i += 1;
                continue;
            }

            if i + 1 >= self.options.len() {
                break;
            }

            let length = self.options[i + 1] as usize;
            if code == option_code {
                if i + 2 + length <= self.options.len() {
                    return Some(self.options[i + 2..i + 2 + length].to_vec());
                }
                break;
            }

            i += 2 + length;
        }
        None
    }

    /// Get the DHCP message type
    pub fn get_message_type(&self) -> Option<MessageType> {
        self.get_option(DhcpOption::MessageType as u8)
            .and_then(|data| data.first().copied())
            .and_then(|value| MessageType::try_from(value).ok())
    }

    /// Get the requested IP address
    pub fn get_requested_ip(&self) -> Option<Ipv4Addr> {
        self.get_option(DhcpOption::RequestedIpAddress as u8).and_then(|data| {
            if data.len() == 4 {
                Some(Ipv4Addr::from([data[0], data[1], data[2], data[3]]))
            } else {
                None
            }
        })
    }

    /// Get the server identifier
    pub fn get_server_identifier(&self) -> Option<Ipv4Addr> {
        self.get_option(DhcpOption::ServerIdentifier as u8).and_then(|data| {
            if data.len() == 4 {
                Some(Ipv4Addr::from([data[0], data[1], data[2], data[3]]))
            } else {
                None
            }
        })
    }

    /// Check if this is a PXE client
    pub fn is_pxe_client(&self) -> bool {
        self.get_option(DhcpOption::VendorClassIdentifier as u8)
            .map(|data| {
                let vendor_class = String::from_utf8_lossy(&data);
                vendor_class.starts_with("PXEClient")
            })
            .unwrap_or(false)
    }

    /// Add an option to the packet
    pub fn add_option(&mut self, code: u8, data: &[u8]) {
        // Remove end option if present - search from the end to find the actual end option
        if let Some(pos) = self.options.iter().rposition(|&x| x == 255) {
            // Only truncate if this 255 is actually an end option (not part of data)
            // Check if it's at a valid option boundary
            if pos == self.options.len() - 1 {
                // Last byte is 255, likely an end option
                self.options.truncate(pos);
            } else {
                // Find the real end by parsing options properly
                let mut real_end = None;
                let mut i = 0;
                while i < self.options.len() {
                    let option_code = self.options[i];
                    if option_code == 255 {
                        real_end = Some(i);
                        break;
                    }
                    if option_code == 0 {
                        i += 1;
                        continue;
                    }
                    if i + 1 >= self.options.len() {
                        break;
                    }
                    let length = self.options[i + 1] as usize;
                    i += 2 + length;
                }
                if let Some(end_pos) = real_end {
                    self.options.truncate(end_pos);
                }
            }
        }

        self.options.push(code);
        self.options.push(data.len() as u8);
        self.options.extend_from_slice(data);

        // Add end option
        self.options.push(255);
    }

    /// Add a u32 option
    pub fn add_u32_option(&mut self, code: u8, value: u32) {
        self.add_option(code, &value.to_be_bytes());
    }

    /// Add an IP address option
    pub fn add_ip_option(&mut self, code: u8, ip: Ipv4Addr) {
        self.add_option(code, &ip.octets());
    }

    /// Add a string option
    pub fn add_string_option(&mut self, code: u8, value: &str) {
        self.add_option(code, value.as_bytes());
    }

    /// Create a response packet based on this request
    pub fn create_response(&self, message_type: MessageType) -> DhcpPacket {
        let mut response = DhcpPacket::new();
        response.op = OpCode::BootReply;
        response.htype = self.htype;
        response.hlen = self.hlen;
        response.xid = self.xid;
        response.flags = self.flags;
        response.giaddr = self.giaddr;
        response.chaddr = self.chaddr;

        // Add message type option
        response.add_option(DhcpOption::MessageType as u8, &[message_type as u8]);

        response
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_packet_creation() {
        let packet = DhcpPacket::new();
        assert_eq!(packet.op, OpCode::BootRequest);
        assert_eq!(packet.htype, HardwareType::Ethernet);
        assert_eq!(packet.hlen, 6);
    }

    #[test]
    fn test_mac_address() {
        let mut packet = DhcpPacket::new();
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        packet.set_mac_address(mac);
        assert_eq!(packet.get_mac_address(), mac);
    }

    #[test]
    fn test_options() {
        let mut packet = DhcpPacket::new();

        // Add message type option
        packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

        // Get message type
        assert_eq!(packet.get_message_type().unwrap(), MessageType::Discover);

        // Add IP option
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        packet.add_ip_option(DhcpOption::RequestedIpAddress as u8, ip);
        assert_eq!(packet.get_requested_ip().unwrap(), ip);
    }

    #[test]
    fn test_packet_serialization() {
        let mut packet = DhcpPacket::new();
        packet.xid = 0x12345678;
        packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

        let bytes = packet.to_bytes();
        assert!(bytes.len() >= 300); // Minimum packet size

        let parsed = DhcpPacket::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.xid, 0x12345678);
        assert_eq!(parsed.get_message_type().unwrap(), MessageType::Discover);
    }

    #[test]
    fn test_pxe_detection() {
        let mut packet = DhcpPacket::new();

        // Non-PXE client
        assert!(!packet.is_pxe_client());

        // PXE client
        packet.add_string_option(
            DhcpOption::VendorClassIdentifier as u8,
            "PXEClient:Arch:00000:UNDI:002001",
        );
        assert!(packet.is_pxe_client());
    }

    #[test]
    fn test_response_creation() {
        let mut request = DhcpPacket::new();
        request.xid = 0x12345678;
        request.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        let response = request.create_response(MessageType::Offer);
        assert_eq!(response.op, OpCode::BootReply);
        assert_eq!(response.xid, request.xid);
        assert_eq!(response.get_mac_address(), request.get_mac_address());
        assert_eq!(response.get_message_type().unwrap(), MessageType::Offer);
    }
}
