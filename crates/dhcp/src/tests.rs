use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::time::timeout;

use crate::packet::DhcpPacket;
use crate::server::{DhcpConfig, DhcpServer};
use crate::{DhcpOption, IpPool, MessageType, OpCode};

#[test]
fn test_dhcp_config_default() {
    let config = DhcpConfig::default();
    assert_eq!(config.bind, "0.0.0.0:67");
    assert_eq!(config.pool_start, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(config.pool_end, Ipv4Addr::new(192, 168, 1, 200));
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
fn test_dhcp_discover_packet_creation() {
    let mut packet = DhcpPacket::new();
    packet.xid = 0x12345678;
    packet.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

    assert_eq!(packet.get_message_type().unwrap(), MessageType::Discover);
    assert_eq!(packet.get_mac_address(), [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(packet.xid, 0x12345678);
}

#[test]
fn test_dhcp_request_packet_creation() {
    let mut packet = DhcpPacket::new();
    packet.xid = 0x87654321;
    packet.set_mac_address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Request as u8]);
    packet.add_ip_option(DhcpOption::RequestedIpAddress as u8, Ipv4Addr::new(192, 168, 1, 150));
    packet.add_ip_option(DhcpOption::ServerIdentifier as u8, Ipv4Addr::new(192, 168, 1, 1));

    assert_eq!(packet.get_message_type().unwrap(), MessageType::Request);
    assert_eq!(packet.get_requested_ip().unwrap(), Ipv4Addr::new(192, 168, 1, 150));
    assert_eq!(packet.get_server_identifier().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
}

#[test]
fn test_pxe_client_detection() {
    let mut packet = DhcpPacket::new();

    // Non-PXE client
    assert!(!packet.is_pxe_client());

    // PXE UEFI client
    packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00007:UNDI:003000",
    );
    assert!(packet.is_pxe_client());
}

#[test]
fn test_dhcp_offer_response() {
    let mut discover = DhcpPacket::new();
    discover.xid = 0x12345678;
    discover.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    discover.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);

    let offer = discover.create_response(MessageType::Offer);
    assert_eq!(offer.op, OpCode::BootReply);
    assert_eq!(offer.xid, discover.xid);
    assert_eq!(offer.get_mac_address(), discover.get_mac_address());
    assert_eq!(offer.get_message_type().unwrap(), MessageType::Offer);
}

#[test]
fn test_dhcp_ack_response() {
    let mut request = DhcpPacket::new();
    request.xid = 0x87654321;
    request.set_mac_address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    request.add_option(DhcpOption::MessageType as u8, &[MessageType::Request as u8]);

    let ack = request.create_response(MessageType::Ack);
    assert_eq!(ack.op, OpCode::BootReply);
    assert_eq!(ack.xid, request.xid);
    assert_eq!(ack.get_mac_address(), request.get_mac_address());
    assert_eq!(ack.get_message_type().unwrap(), MessageType::Ack);
}

#[test]
fn test_dhcp_packet_serialization_roundtrip() {
    let mut packet = DhcpPacket::new();
    packet.xid = 0x12345678;
    packet.flags = 0x8000; // Broadcast flag
    packet.yiaddr = Ipv4Addr::new(192, 168, 1, 150);
    packet.siaddr = Ipv4Addr::new(192, 168, 1, 1);
    packet.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Add various options
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Offer as u8]);
    packet.add_ip_option(DhcpOption::SubnetMask as u8, Ipv4Addr::new(255, 255, 255, 0));
    packet.add_ip_option(DhcpOption::Router as u8, Ipv4Addr::new(192, 168, 1, 1));
    packet.add_u32_option(DhcpOption::IpAddressLeaseTime as u8, 3600);
    packet.add_string_option(DhcpOption::DomainName as u8, "example.com");

    // Serialize and deserialize
    let bytes = packet.to_bytes();
    let parsed = DhcpPacket::from_bytes(&bytes).unwrap();

    // Verify core fields
    assert_eq!(parsed.xid, packet.xid);
    assert_eq!(parsed.flags, packet.flags);
    assert_eq!(parsed.yiaddr, packet.yiaddr);
    assert_eq!(parsed.siaddr, packet.siaddr);
    assert_eq!(parsed.get_mac_address(), packet.get_mac_address());

    // Verify options
    assert_eq!(parsed.get_message_type().unwrap(), MessageType::Offer);

    // Verify subnet mask option
    let subnet_mask_option = parsed.get_option(DhcpOption::SubnetMask as u8).unwrap();
    assert_eq!(subnet_mask_option.len(), 4);
    let subnet_ip = Ipv4Addr::from([
        subnet_mask_option[0],
        subnet_mask_option[1],
        subnet_mask_option[2],
        subnet_mask_option[3],
    ]);
    assert_eq!(subnet_ip, Ipv4Addr::new(255, 255, 255, 0));

    // Verify router option
    let router_option = parsed.get_option(DhcpOption::Router as u8).unwrap();
    assert_eq!(router_option.len(), 4);
    let router_ip = Ipv4Addr::from([router_option[0], router_option[1], router_option[2], router_option[3]]);
    assert_eq!(router_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(
        u32::from_be_bytes(
            parsed
                .get_option(DhcpOption::IpAddressLeaseTime as u8)
                .unwrap()
                .try_into()
                .unwrap()
        ),
        3600
    );
    assert_eq!(
        String::from_utf8(parsed.get_option(DhcpOption::DomainName as u8).unwrap()).unwrap(),
        "example.com"
    );
}

#[test]
fn test_dhcp_packet_options_debug() {
    let mut packet = DhcpPacket::new();

    // Add options one by one and check serialization
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Offer as u8]);
    println!("After MessageType: options = {:?}", packet.options);

    packet.add_ip_option(DhcpOption::SubnetMask as u8, Ipv4Addr::new(255, 255, 255, 0));
    println!("After SubnetMask: options = {:?}", packet.options);

    packet.add_ip_option(DhcpOption::Router as u8, Ipv4Addr::new(192, 168, 1, 1));
    println!("After Router: options = {:?}", packet.options);

    // Serialize and check raw bytes
    let bytes = packet.to_bytes();
    println!("Full packet length: {}", bytes.len());
    if bytes.len() >= 240 {
        println!("Magic cookie: {:?}", &bytes[236..240]);
        println!("Options section: {:?}", &bytes[240..]);
    }

    // Parse and check what we get back
    let parsed = DhcpPacket::from_bytes(&bytes).unwrap();
    println!("Parsed options: {:?}", parsed.options);

    // Check each option individually
    println!(
        "MessageType option: {:?}",
        parsed.get_option(DhcpOption::MessageType as u8)
    );
    println!(
        "SubnetMask option: {:?}",
        parsed.get_option(DhcpOption::SubnetMask as u8)
    );
    println!("Router option: {:?}", parsed.get_option(DhcpOption::Router as u8));
}

#[test]
fn test_ip_pool_allocation() {
    let mut pool = IpPool::new(Ipv4Addr::new(10, 0, 1, 100), Ipv4Addr::new(10, 0, 1, 105));

    let mac1 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let mac2 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let mac3 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x07];

    // First allocation
    let ip1 = pool.allocate(mac1).unwrap();
    assert_eq!(ip1, Ipv4Addr::new(10, 0, 1, 100));

    // Same MAC should get same IP
    let ip1_again = pool.allocate(mac1).unwrap();
    assert_eq!(ip1, ip1_again);

    // Different MAC should get different IP
    let ip2 = pool.allocate(mac2).unwrap();
    assert_ne!(ip1, ip2);

    // Third allocation
    let ip3 = pool.allocate(mac3).unwrap();
    assert_ne!(ip1, ip3);
    assert_ne!(ip2, ip3);

    // Release and reallocate
    pool.release(mac1);
    let ip1_new = pool.allocate(mac1).unwrap();
    assert!(ip1_new == Ipv4Addr::new(10, 0, 1, 100) || ip1_new != ip2 && ip1_new != ip3);
}

#[test]
fn test_ip_pool_exhaustion() {
    // Small pool with only 2 IPs
    let mut pool = IpPool::new(Ipv4Addr::new(192, 168, 1, 100), Ipv4Addr::new(192, 168, 1, 101));

    let mac1 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let mac2 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x06];
    let mac3 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x07];

    // Allocate both IPs
    assert!(pool.allocate(mac1).is_some());
    assert!(pool.allocate(mac2).is_some());

    // Third allocation should fail
    assert!(pool.allocate(mac3).is_none());

    // Release one and try again
    pool.release(mac1);
    assert!(pool.allocate(mac3).is_some());
}

#[test]
fn test_dhcp_options_parsing() {
    let mut packet = DhcpPacket::new();

    // Test various option types
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);
    packet.add_ip_option(DhcpOption::RequestedIpAddress as u8, Ipv4Addr::new(10, 0, 0, 100));
    packet.add_u32_option(DhcpOption::IpAddressLeaseTime as u8, 7200);
    packet.add_string_option(DhcpOption::DomainName as u8, "test.local");

    // Test retrieval
    assert_eq!(packet.get_message_type().unwrap(), MessageType::Discover);
    assert_eq!(packet.get_requested_ip().unwrap(), Ipv4Addr::new(10, 0, 0, 100));

    let lease_time_bytes = packet.get_option(DhcpOption::IpAddressLeaseTime as u8).unwrap();
    let lease_time = u32::from_be_bytes(lease_time_bytes.try_into().unwrap());
    assert_eq!(lease_time, 7200);

    let domain_bytes = packet.get_option(DhcpOption::DomainName as u8).unwrap();
    let domain = String::from_utf8(domain_bytes).unwrap();
    assert_eq!(domain, "test.local");
}

#[test]
fn test_dhcp_packet_validation() {
    // Test minimum packet size
    let short_packet = vec![0u8; 100];
    assert!(DhcpPacket::from_bytes(&short_packet).is_err());

    // Test invalid op code
    let mut invalid_packet = vec![0u8; 300];
    invalid_packet[0] = 99; // Invalid op code
    assert!(DhcpPacket::from_bytes(&invalid_packet).is_err());

    // Test unsupported hardware type
    let mut invalid_packet = vec![0u8; 300];
    invalid_packet[0] = 1; // Valid op code
    invalid_packet[1] = 99; // Invalid hardware type
    assert!(DhcpPacket::from_bytes(&invalid_packet).is_err());
}

#[test]
fn test_message_type_conversion() {
    // Test valid conversions
    assert_eq!(MessageType::try_from(1).unwrap(), MessageType::Discover);
    assert_eq!(MessageType::try_from(2).unwrap(), MessageType::Offer);
    assert_eq!(MessageType::try_from(3).unwrap(), MessageType::Request);
    assert_eq!(MessageType::try_from(5).unwrap(), MessageType::Ack);
    assert_eq!(MessageType::try_from(6).unwrap(), MessageType::Nak);

    // Test invalid conversion
    assert!(MessageType::try_from(99).is_err());
}

#[test]
fn test_broadcast_flag_handling() {
    let mut packet = DhcpPacket::new();

    // Test broadcast flag not set
    assert_eq!(packet.flags & 0x8000, 0);

    // Test broadcast flag set
    packet.flags = 0x8000;
    assert_eq!(packet.flags & 0x8000, 0x8000);
}

#[test]
fn test_pxe_architecture_detection() {
    // Test UEFI x64 client
    let mut uefi_packet = DhcpPacket::new();
    uefi_packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00007:UNDI:003000",
    );
    assert!(uefi_packet.is_pxe_client());

    // Test EFI BC client
    let mut efi_packet = DhcpPacket::new();
    efi_packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00009:UNDI:003000",
    );
    assert!(efi_packet.is_pxe_client());
}

#[test]
fn test_dhcp_release_packet() {
    let mut packet = DhcpPacket::new();
    packet.xid = 0x11223344;
    packet.ciaddr = Ipv4Addr::new(192, 168, 1, 150);
    packet.set_mac_address([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Release as u8]);
    packet.add_ip_option(DhcpOption::ServerIdentifier as u8, Ipv4Addr::new(192, 168, 1, 1));

    assert_eq!(packet.get_message_type().unwrap(), MessageType::Release);
    assert_eq!(packet.ciaddr, Ipv4Addr::new(192, 168, 1, 150));
    assert_eq!(packet.get_server_identifier().unwrap(), Ipv4Addr::new(192, 168, 1, 1));
}

#[tokio::test]
async fn test_dhcp_server_bind_error() {
    // Try to bind to an invalid address
    let config = DhcpConfig {
        bind: "999.999.999.999:67".to_string(),
        server_identifier: Ipv4Addr::new(127, 0, 0, 1),
        tftp_server: Ipv4Addr::new(127, 0, 0, 1),
        router: Ipv4Addr::new(127, 0, 0, 1),
        ..Default::default()
    };

    let server = DhcpServer::new(config);
    let result = timeout(Duration::from_millis(100), server.run()).await;

    // Should either timeout or return an error
    assert!(result.is_err() || result.unwrap().is_err());
}
