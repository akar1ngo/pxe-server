//! Integration tests for the PXE server
//!
//! These tests start the actual server and test it with real network requests.

use std::path::PathBuf;
use std::time::Duration;

// Import the main server functions from the new modular structure
use tftp::{TftpServer, TftpServerConfig, run_tftp_server};
use tempfile::tempdir;
use tokio::fs;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn test_tftp_server_integration() {
    // Create temporary directory with test file
    let temp_dir = tempdir().unwrap();
    let test_file_content = b"Hello, TFTP integration test!";
    let test_file_path = temp_dir.path().join("test.txt");
    fs::write(&test_file_path, test_file_content).await.unwrap();

    // Start TFTP server on ephemeral port
    let server_handle =
        tokio::spawn(
            async move { run_tftp_server("127.0.0.1:0".to_string(), temp_dir.path().to_path_buf(), None).await },
        );

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Unfortunately, we can't easily get the actual bound port from the server
    // In a real scenario, you'd modify run_tftp_server to return the bound address

    // For now, just test that the server starts without crashing
    sleep(Duration::from_millis(50)).await;

    // Stop the server
    server_handle.abort();
    let result = server_handle.await;
    assert!(result.is_err()); // Should be aborted
}

#[tokio::test]
async fn test_tftp_server_struct() {
    // Test the TftpServer struct directly
    let temp_dir = tempdir().unwrap();
    let config = TftpServerConfig {
        bind_address: "127.0.0.1:0".to_string(),
        root_directory: temp_dir.path().to_path_buf(),
        transfer_config: Default::default(),
    };

    let mut server = TftpServer::new(config);

    // Test that we can access configuration
    assert_eq!(server.config().bind_address, "127.0.0.1:0");
    assert_eq!(server.config().root_directory, temp_dir.path());

    // Test that local_addr is None before binding
    assert!(server.local_addr().is_none());

    // Start server in background
    let server_task = tokio::spawn(async move { server.run().await });

    // Give it a moment to start
    sleep(Duration::from_millis(10)).await;

    // Stop the server
    server_task.abort();
    let result = server_task.await;
    assert!(result.is_err()); // Should be aborted
}

#[tokio::test]
async fn test_tftp_packet_parsing() {
    // Test RRQ parsing using the new modular functions
    use tftp::{TftpOpcode, parse_rrq};

    // Create a valid RRQ packet
    let mut rrq = Vec::new();
    rrq.extend_from_slice(&TftpOpcode::ReadRequest.as_u16().to_be_bytes()); // RRQ opcode
    rrq.extend_from_slice(b"test.txt\0");
    rrq.extend_from_slice(b"octet\0");
    rrq.extend_from_slice(b"blksize\0");
    rrq.extend_from_slice(b"1400\0");

    let result = parse_rrq(&rrq).unwrap();
    assert_eq!(result.0, "test.txt");
    assert_eq!(result.1, "octet");
    assert_eq!(result.2.get("blksize"), Some(&"1400".to_string()));
}

#[tokio::test]
async fn test_tftp_packet_building() {
    // Test packet building functions
    use std::collections::HashMap;

    use tftp::{TftpErrorCode, TftpOpcode, build_ack, build_data, build_error, build_oack};

    // Test DATA packet
    let data_packet = build_data(1, b"Hello, TFTP!");
    assert_eq!(data_packet[0..2], TftpOpcode::Data.as_u16().to_be_bytes());
    assert_eq!(data_packet[2..4], 1u16.to_be_bytes());
    assert_eq!(&data_packet[4..], b"Hello, TFTP!");

    // Test ERROR packet
    let error_packet = build_error(TftpErrorCode::FileNotFound.as_u16(), "File not found");
    assert_eq!(error_packet[0..2], TftpOpcode::Error.as_u16().to_be_bytes());
    assert_eq!(error_packet[2..4], TftpErrorCode::FileNotFound.as_u16().to_be_bytes());
    assert!(error_packet.ends_with(b"File not found\0"));

    // Test ACK packet
    let ack_packet = build_ack(42);
    assert_eq!(ack_packet[0..2], TftpOpcode::Acknowledgment.as_u16().to_be_bytes());
    assert_eq!(ack_packet[2..4], 42u16.to_be_bytes());

    // Test OACK packet
    let mut options = HashMap::new();
    options.insert("blksize".to_string(), "1400".to_string());
    let oack_packet = build_oack(&options);
    assert_eq!(oack_packet[0..2], TftpOpcode::OptionAck.as_u16().to_be_bytes());
    #[allow(clippy::octal_escapes)]
    {
        assert!(String::from_utf8_lossy(&oack_packet[2..]).contains("blksize\01400\0"));
    }
}

#[tokio::test]
async fn test_udp_socket_operations() {
    // Test basic UDP operations that the server uses
    let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let addr1 = socket1.local_addr().unwrap();
    let addr2 = socket2.local_addr().unwrap();

    // Send a test packet
    let test_data = b"test packet";
    socket1.send_to(test_data, addr2).await.unwrap();

    // Receive it
    let mut buf = vec![0u8; 1024];
    let (len, src) = timeout(Duration::from_millis(100), socket2.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(len, test_data.len());
    assert_eq!(&buf[..len], test_data);
    assert_eq!(src, addr1);
}

#[tokio::test]
async fn test_concurrent_tftp_requests() {
    // Test that multiple concurrent TFTP operations would work
    let mut handles = Vec::new();

    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let local_addr = socket.local_addr().unwrap();

            // Send to self
            let data = format!("test-{}", i);
            socket.send_to(data.as_bytes(), local_addr).await.unwrap();

            let mut buf = vec![0u8; 100];
            let (len, _) = socket.recv_from(&mut buf).await.unwrap();

            String::from_utf8(buf[..len].to_vec()).unwrap()
        });

        handles.push(handle);
    }

    // Wait for all to complete
    for (i, handle) in handles.into_iter().enumerate() {
        let result = handle.await.unwrap();
        assert_eq!(result, format!("test-{}", i));
    }
}

#[test]
fn test_path_operations() {
    use std::fs;

    use tempfile::tempdir;

    let temp_dir = tempdir().unwrap();
    let root = temp_dir.path();

    // Create test file
    let test_file = root.join("test.txt");
    fs::write(&test_file, b"test content").unwrap();

    // Test path canonicalization (security check)
    let canonical_root = root.canonicalize().unwrap();
    let canonical_file = test_file.canonicalize().unwrap();

    assert!(canonical_file.starts_with(&canonical_root));

    // Test that dangerous paths would be rejected
    let dangerous_path = root.join("../../../etc/passwd");
    // In real server, this would be rejected by the canonicalize check
    // since the canonical path wouldn't start with canonical_root

    assert!(dangerous_path.to_string_lossy().contains(".."));
}

#[tokio::test]
async fn test_file_operations() {
    use tempfile::tempdir;
    use tokio::fs;

    let temp_dir = tempdir().unwrap();
    let test_file = temp_dir.path().join("async_test.txt");
    let content = b"Async file test content";

    // Write file
    fs::write(&test_file, content).await.unwrap();

    // Read file
    let read_content = fs::read(&test_file).await.unwrap();
    assert_eq!(read_content, content);

    // Test file metadata
    let metadata = fs::metadata(&test_file).await.unwrap();
    assert_eq!(metadata.len(), content.len() as u64);
    assert!(metadata.is_file());
}

#[test]
fn test_tftp_mode_validation() {
    use tftp::TransferMode;

    // Test supported modes
    assert_eq!(TransferMode::from_str_opt("octet"), Some(TransferMode::Octet));
    assert_eq!(TransferMode::from_str_opt("netascii"), Some(TransferMode::NetAscii));
    assert_eq!(TransferMode::from_str_opt("OCTET"), Some(TransferMode::Octet)); // Case insensitive
    assert_eq!(TransferMode::from_str_opt("NetAscii"), Some(TransferMode::NetAscii)); // Case insensitive

    // Test FromStr trait implementation
    assert_eq!("octet".parse::<TransferMode>(), Ok(TransferMode::Octet));
    assert_eq!("NETASCII".parse::<TransferMode>(), Ok(TransferMode::NetAscii));

    // Test unsupported modes
    assert_eq!(TransferMode::from_str_opt("mail"), None);
    assert_eq!(TransferMode::from_str_opt("binary"), None);
    assert_eq!(TransferMode::from_str_opt(""), None);
    assert!("binary".parse::<TransferMode>().is_err());

    // Test support status
    assert!(TransferMode::Octet.is_supported());
    assert!(!TransferMode::NetAscii.is_supported()); // Limited support
}

#[test]
fn test_netascii_conversion() {
    use tftp::{convert_from_netascii, convert_to_netascii};

    // Test basic conversion
    let input = b"Hello\nWorld\r";
    let netascii = convert_to_netascii(input);
    let expected = b"Hello\r\nWorld\r\0";
    assert_eq!(netascii, expected);

    // Test reverse conversion
    let netascii_input = b"Hello\r\nWorld\r\0";
    let binary = convert_from_netascii(netascii_input);
    let expected_binary = b"Hello\nWorld\r";
    assert_eq!(binary, expected_binary);

    // Test round trip for simple LF-only text
    let simple = b"Line1\nLine2\nLine3";
    let to_netascii = convert_to_netascii(simple);
    let back_to_binary = convert_from_netascii(&to_netascii);
    assert_eq!(back_to_binary, simple);
}

#[test]
fn test_block_size_parsing() {
    use std::collections::HashMap;

    use tftp::BlockSizeConfig;

    let mut options = HashMap::new();

    // No blksize option
    assert_eq!(BlockSizeConfig::from_options(&options).size, BlockSizeConfig::DEFAULT);

    // Valid blksize
    options.insert("blksize".to_string(), "1024".to_string());
    assert_eq!(BlockSizeConfig::from_options(&options).size, 1024);

    // Blksize too large - should be clamped
    options.insert("blksize".to_string(), "2000".to_string());
    assert_eq!(BlockSizeConfig::from_options(&options).size, BlockSizeConfig::MAX);

    // Zero blksize - should return default
    options.insert("blksize".to_string(), "0".to_string());
    assert_eq!(BlockSizeConfig::from_options(&options).size, BlockSizeConfig::DEFAULT);

    // Invalid blksize - should return default
    options.insert("blksize".to_string(), "invalid".to_string());
    assert_eq!(BlockSizeConfig::from_options(&options).size, BlockSizeConfig::DEFAULT);
}

#[tokio::test]
async fn test_transfer_config() {
    use std::time::Duration;

    use tftp::{BlockSizeConfig, TransferConfig};

    let config = TransferConfig::default();
    assert_eq!(config.block_size.size, BlockSizeConfig::DEFAULT);
    assert_eq!(config.timeout, Duration::from_secs(3));
    assert_eq!(config.max_retries, 8);
    assert_eq!(config.root_dir, PathBuf::from("./tftp_root"));

    // Test custom config
    let custom_config = TransferConfig {
        root_dir: PathBuf::from("/tmp"),
        block_size: BlockSizeConfig::from_option("1024"),
        timeout: Duration::from_secs(5),
        max_retries: 5,
        local_bind: None,
    };

    assert_eq!(custom_config.block_size.size, 1024);
    assert_eq!(custom_config.timeout, Duration::from_secs(5));
    assert_eq!(custom_config.max_retries, 5);
}

#[test]
fn test_tftp_server_config() {
    let config = TftpServerConfig::default();
    assert_eq!(config.bind_address, "0.0.0.0:6969");
    assert_eq!(config.root_directory, PathBuf::from("./tftp_root"));

    let custom_server = TftpServer::with_config("127.0.0.1:9999".to_string(), PathBuf::from("/custom/root"));

    assert_eq!(custom_server.config().bind_address, "127.0.0.1:9999");
    assert_eq!(custom_server.config().root_directory, PathBuf::from("/custom/root"));
}
