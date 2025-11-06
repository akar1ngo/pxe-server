//! Simple DHCP test client to verify our server can receive packets

use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use nix::net::if_::if_nametoindex;
use pxe_server::dhcp::packet::DhcpPacket;
use pxe_server::dhcp::{DhcpOption, MessageType};
use socket2::{Domain, Protocol, Socket, Type};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("DHCP Test Client - Sending test packet to verify server reception");

    // Create a DHCP Discover packet
    let mut packet = DhcpPacket::new();
    packet.xid = 0x12345678;
    packet.set_mac_address([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Add DHCP options
    packet.add_option(DhcpOption::MessageType as u8, &[MessageType::Discover as u8]);
    packet.add_string_option(
        DhcpOption::VendorClassIdentifier as u8,
        "PXEClient:Arch:00007:UNDI:003016",
    );

    let packet_data = packet.to_bytes();

    println!("Created DHCP Discover packet ({} bytes)", packet_data.len());
    println!("XID: 0x{:08x}", packet.xid);
    println!(
        "MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        packet.chaddr[0], packet.chaddr[1], packet.chaddr[2], packet.chaddr[3], packet.chaddr[4], packet.chaddr[5]
    );

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if let Ok(interface) = if_nametoindex("en8") {
        socket.bind_device_by_index_v4(NonZeroU32::new(interface))?;
    }
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    let address: SocketAddr = "0.0.0.0:68".parse()?;
    socket.bind(&address.into())?;

    // Test both broadcast and direct delivery
    let test_addresses = vec![("127.0.0.1:67", "localhost"), ("255.255.255.255:67", "broadcast")];

    for (addr_str, addr_type) in test_addresses {
        let server_addr: SocketAddr = addr_str.parse()?;
        println!("\n--- Testing {} delivery to {} ---", addr_type, server_addr);

        socket.send_to(&packet_data, &server_addr.into())?;
        println!("Packet sent successfully");

        // Try to receive a response
        let mut buffer = [MaybeUninit::uninit(); 1500];
        match socket.recv_from(&mut buffer) {
            Ok((len, addr)) => {
                println!("✓ Received response ({} bytes) from {:?}", len, addr);

                let bytes = unsafe { assume_init_ref(&buffer[..len]) };

                // Try to parse the response
                if let Ok(response) = DhcpPacket::from_bytes(bytes)
                    && let Some(msg_type) = response.get_message_type()
                {
                    println!("  Response type: {:?}", msg_type);
                    println!("  Response XID: 0x{:08x}", response.xid);
                    if response.xid == packet.xid {
                        println!("  ✓ XID matches - this is our response!");
                        println!("  ✓ {} delivery works!", addr_type);
                    } else {
                        println!("  ⚠ XID mismatch - this might be for another client");
                    }
                }
                break; // Exit on first successful response
            }
            Err(e) => {
                println!("✗ No response received for {} delivery: {}", addr_type, e);
                if addr_type == "broadcast" {
                    println!("  This suggests broadcast reception issues on the server");
                } else {
                    println!("  This suggests the server is not running or not responding at all");
                }
            }
        }
    }

    Ok(())
}

const unsafe fn assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
}
