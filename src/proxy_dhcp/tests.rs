//! Tests for the Proxy DHCP server
//!
//! These tests verify that the proxy DHCP server correctly handles PXE client requests
//! and generates appropriate responses using the shared DHCP module types.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use super::*;
use crate::dhcp::packet::DhcpPacket;
use crate::dhcp::{DhcpOption, HardwareType, MessageType, OpCode};

/// Create a test PXE DISCOVER request packet for BIOS clients
fn create_bios_discover_request() -> DhcpPacket {
    let mut packet = DhcpPacket::new();
    packet.op = OpCode::BootRequest;
    packet.htype = HardwareType::Ethernet;
    packet.hlen = 6;
    packet.xid = 0x12345678;
    packet.flags = 0x8000; // Broadcast flag
    packet.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Add DHCP message type
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

    // Add PXE vendor class identifier for BIOS
    packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00000:UNDI:002001",
    );

    packet
}

/// Create a test PXE DISCOVER request packet for UEFI clients
fn create_uefi_discover_request() -> DhcpPacket {
    let mut packet = DhcpPacket::new();
    packet.op = OpCode::BootRequest;
    packet.htype = HardwareType::Ethernet;
    packet.hlen = 6;
    packet.xid = 0x87654321;
    packet.flags = 0x8000; // Broadcast flag
    packet.set_mac_address([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

    // Add DHCP message type
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

    // Add PXE vendor class identifier for UEFI
    packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00007:UNDI:003001",
    );

    packet
}

/// Create a test PXE REQUEST packet
fn create_pxe_request(server_id: Ipv4Addr) -> DhcpPacket {
    let mut packet = DhcpPacket::new();
    packet.op = OpCode::BootRequest;
    packet.htype = HardwareType::Ethernet;
    packet.hlen = 6;
    packet.xid = 0xabcdef00;
    packet.set_mac_address([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);

    // Add DHCP message type
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Request as u8]);

    // Add PXE vendor class identifier
    packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00000:UNDI:002001",
    );

    // Add server identifier
    packet.add_ip_option(DhcpOption::ServerIdentifier as u8, server_id);

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
    let server = server::tests::create_test_server(config);
    let request = create_bios_discover_request();

    let bootfile = server.determine_bootfile(&request);
    assert_eq!(bootfile, "pxelinux.0");
}

#[tokio::test]
async fn test_determine_bootfile_uefi() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);
    let request = create_uefi_discover_request();

    let bootfile = server.determine_bootfile(&request);
    assert_eq!(bootfile, "ipxe.efi");
}

#[tokio::test]
async fn test_determine_bootfile_uefi_efi_variant() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);

    let mut request = DhcpPacket::new();
    request.op = OpCode::BootRequest;
    request.htype = HardwareType::Ethernet;
    request.hlen = 6;
    request.xid = 0x12345678;
    request.flags = 0x8000;
    request.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Add DHCP message type
    request.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

    // Add PXE vendor class identifier with EFI variant
    request.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00000:EFI:002001",
    );

    let bootfile = server.determine_bootfile(&request);
    assert_eq!(bootfile, "ipxe.efi");
}

#[tokio::test]
async fn test_create_offer_bios() {
    let config = ProxyConfig {
        tftp_server: Ipv4Addr::new(192, 168, 1, 100),
        bios_bootfile: "test-bios.0".to_string(),
        ..Default::default()
    };
    let server = server::tests::create_test_server(config);
    let request = create_bios_discover_request();

    let offer = server.create_offer(&request, "test-bios.0").unwrap();

    // Verify basic packet structure
    assert_eq!(offer.op, OpCode::BootReply);
    assert_eq!(offer.xid, request.xid);
    assert_eq!(offer.get_mac_address(), request.get_mac_address());
    assert_eq!(offer.get_message_type().unwrap(), MessageType::Offer);

    // Verify TFTP server is set
    assert_eq!(offer.siaddr, Ipv4Addr::new(192, 168, 1, 100));

    // Verify server identifier option
    assert_eq!(offer.get_server_identifier().unwrap(), Ipv4Addr::new(192, 168, 1, 100));

    // Verify boot file is in the file field
    let file_str = std::str::from_utf8(&offer.file).unwrap();
    let file_end = file_str.find('\0').unwrap_or(file_str.len());
    assert_eq!(&file_str[..file_end], "test-bios.0");

    // Verify DHCP options are present
    assert!(offer.get_option(DhcpOption::TftpServerName as u8).is_some());
    assert!(offer.get_option(DhcpOption::BootfileName as u8).is_some());
    assert!(offer.get_option(DhcpOption::VendorSpecificInfo as u8).is_some());
}

#[tokio::test]
async fn test_create_offer_uefi() {
    let config = ProxyConfig {
        tftp_server: Ipv4Addr::new(10, 0, 0, 1),
        efi_bootfile: "test-uefi.efi".to_string(),
        server_identifier: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    let server = server::tests::create_test_server(config);
    let request = create_uefi_discover_request();

    let offer = server.create_offer(&request, "test-uefi.efi").unwrap();

    // Verify basic packet structure
    assert_eq!(offer.op, OpCode::BootReply);
    assert_eq!(offer.xid, request.xid);
    assert_eq!(offer.get_mac_address(), request.get_mac_address());
    assert_eq!(offer.get_message_type().unwrap(), MessageType::Offer);

    // Verify TFTP server is set
    assert_eq!(offer.siaddr, Ipv4Addr::new(10, 0, 0, 1));

    // Verify custom server identifier is used
    assert_eq!(offer.get_server_identifier().unwrap(), Ipv4Addr::new(10, 0, 0, 2));

    // Verify boot file is in the file field
    let file_str = std::str::from_utf8(&offer.file).unwrap();
    let file_end = file_str.find('\0').unwrap_or(file_str.len());
    assert_eq!(&file_str[..file_end], "test-uefi.efi");
}

#[tokio::test]
async fn test_create_ack() {
    let config = ProxyConfig {
        tftp_server: Ipv4Addr::new(172, 16, 0, 1),
        bios_bootfile: "ack-test.0".to_string(),
        ..Default::default()
    };
    let server = server::tests::create_test_server(config);
    let request = create_pxe_request(Ipv4Addr::new(172, 16, 0, 1));

    let ack = server.create_ack(&request, "ack-test.0").unwrap();

    // Verify this is an ACK response
    assert_eq!(ack.get_message_type().unwrap(), MessageType::Ack);
    assert_eq!(ack.op, OpCode::BootReply);
    assert_eq!(ack.xid, request.xid);

    // Verify TFTP server configuration
    assert_eq!(ack.siaddr, Ipv4Addr::new(172, 16, 0, 1));
    assert_eq!(ack.get_server_identifier().unwrap(), Ipv4Addr::new(172, 16, 0, 1));
}

#[tokio::test]
async fn test_determine_destination_unicast() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);

    let mut request = create_bios_discover_request();
    request.flags = 0; // No broadcast flag

    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 68));
    let dest = server.determine_destination(&request, src);

    // Should send back to the source IP
    assert_eq!(
        dest,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 68))
    );
}

#[tokio::test]
async fn test_determine_destination_broadcast_flag() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);

    let mut request = create_bios_discover_request();
    request.flags = 0x8000; // Broadcast flag set

    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 50), 68));
    let dest = server.determine_destination(&request, src);

    // Should broadcast
    assert_eq!(dest, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)));
}

#[tokio::test]
async fn test_determine_destination_unspecified_source() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);

    let mut request = create_bios_discover_request();
    request.flags = 0; // No broadcast flag

    let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68));
    let dest = server.determine_destination(&request, src);

    // Should broadcast when source is unspecified
    assert_eq!(dest, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)));
}

#[tokio::test]
async fn test_vendor_class_echo() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);
    let request = create_bios_discover_request();

    let offer = server.create_offer(&request, "test.0").unwrap();

    // Verify vendor class identifier is echoed back
    let vendor_class = offer.get_option(DhcpOption::VendorClassIdentifier as u8).unwrap();
    let vendor_str = String::from_utf8_lossy(&vendor_class);
    assert_eq!(vendor_str, "PXEClient:Arch:00000:UNDI:002001");
}

#[tokio::test]
async fn test_pxe_vendor_options_included() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);
    let request = create_bios_discover_request();

    let offer = server.create_offer(&request, "test.0").unwrap();

    // Verify PXE vendor-specific options (option 43) are included
    let vendor_options = offer.get_option(DhcpOption::VendorSpecificInfo as u8);
    assert!(vendor_options.is_some());
    assert!(!vendor_options.unwrap().is_empty());
}

#[tokio::test]
async fn test_bootfile_options_consistency() {
    let config = ProxyConfig::default();
    let server = server::tests::create_test_server(config);
    let request = create_bios_discover_request();
    let bootfile = "consistency-test.0";

    let offer = server.create_offer(&request, bootfile).unwrap();

    // Check bootfile in BOOTP file field
    let file_str = std::str::from_utf8(&offer.file).unwrap();
    let file_end = file_str.find('\0').unwrap_or(file_str.len());
    assert_eq!(&file_str[..file_end], bootfile);

    // Check bootfile in DHCP option 67
    let bootfile_option = offer.get_option(DhcpOption::BootfileName as u8).unwrap();
    let bootfile_str = String::from_utf8_lossy(&bootfile_option);
    assert_eq!(bootfile_str, bootfile);
}

#[test]
fn test_non_pxe_client_detection() {
    let mut packet = DhcpPacket::new();
    packet.op = OpCode::BootRequest;
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);
    // No vendor class identifier - should not be detected as PXE client

    assert!(!packet.is_pxe_client());

    // Add non-PXE vendor class
    packet.add_string_option(DhcpOption::VendorClassIdentifier as u8, "SomeOtherClient");
    assert!(!packet.is_pxe_client());
}
