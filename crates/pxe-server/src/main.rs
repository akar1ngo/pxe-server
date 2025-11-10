//! PXE Server - Main executable
//!
//! A lightweight PXE (Preboot Execution Environment) server providing DHCP, ProxyDHCP, and TFTP services.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use argh::FromArgs;
use dhcp::{spawn_dhcp_server, DhcpConfig};
use nix::net::if_::if_nametoindex;
use proxy_dhcp::{spawn_proxy_dhcp_server, ProxyConfig};
use tftp::run_tftp_server;

const DEFAULT_BIND: &str = "0.0.0.0:6969"; // use 6969 for non-root testing; redirect or run as root for :69
const DEFAULT_ROOT: &str = "./tftp_root";

/// Configuration for the TFTP service
#[derive(Debug, Clone)]
pub struct TftpServiceConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub root_directory: PathBuf,
    pub server_ip: std::net::Ipv4Addr,
}

/// Configuration for the ProxyDHCP service
#[derive(Debug, Clone)]
pub struct ProxyDhcpServiceConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub tftp_server: std::net::Ipv4Addr,
    pub bios_bootfile: String,
    pub efi_bootfile: String,
}

/// Configuration for the DHCP service
#[derive(Debug, Clone)]
pub struct DhcpServiceConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub pool_start: std::net::Ipv4Addr,
    pub pool_end: std::net::Ipv4Addr,
    pub subnet_mask: std::net::Ipv4Addr,
    pub router: std::net::Ipv4Addr,
    pub dns_server: std::net::Ipv4Addr,
    pub tftp_server: std::net::Ipv4Addr,
    pub bios_bootfile: String,
    pub efi_bootfile: String,
}

/// Complete service configuration
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub interface: String,
    pub tftp: TftpServiceConfig,
    pub proxy_dhcp: ProxyDhcpServiceConfig,
    pub dhcp: DhcpServiceConfig,
}

#[derive(FromArgs, Debug)]
#[argh(
    description = "PXE Server - TFTP, ProxyDHCP, and DHCP server for network booting",
    example = "Start full PXE server with DHCP:\n  {command_name} --interface eth0 --enable-dhcp --root ./boot --ip 10.0.1.50",
    example = "ProxyDHCP only (requires existing DHCP server):\n  {command_name} --interface eth0 --root ./boot --ip 10.0.1.50",
    example = "TFTP server only:\n  {command_name} --interface eth0 --disable-proxy-dhcp --disable-dhcp --tftp 0.0.0.0:69 --root /tftpboot",
    example = "Custom DHCP configuration:\n  {command_name} --interface eth0 --enable-dhcp --pool-start 10.0.1.100 --pool-end 10.0.1.200 --router 10.0.1.1"
)]
struct CliConfig {
    #[argh(option, short = 'I', description = "network interface to use (required)")]
    interface: String,

    //
    // TFTP Configuration
    //
    #[argh(switch, description = "disable TFTP server")]
    disable_tftp: bool,

    #[argh(
        option,
        short = 'r',
        description = "tftp root directory",
        default = "PathBuf::from(DEFAULT_ROOT)"
    )]
    root: PathBuf,

    #[argh(
        option,
        short = 't',
        description = "tftp server bind address",
        default = "DEFAULT_BIND.to_string()"
    )]
    tftp: String,

    #[argh(
        option,
        short = 'i',
        description = "tftp server IP address",
        default = "\"0.0.0.0\".to_string()"
    )]
    ip: String,

    //
    // ProxyDHCP Configuration
    //
    #[argh(switch, description = "disable ProxyDHCP server")]
    disable_proxy_dhcp: bool,

    #[argh(
        option,
        short = 'p',
        description = "proxyDHCP bind address",
        default = "\"0.0.0.0\".to_string()"
    )]
    proxy: String,

    //
    // DHCP Configuration
    //
    #[argh(switch, short = 'D', description = "enable DHCP server (provides IP addresses)")]
    enable_dhcp: bool,

    #[argh(
        option,
        short = 'd',
        description = "dhcp server bind address",
        default = "\"0.0.0.0:67\".to_string()"
    )]
    dhcp: String,

    #[argh(
        option,
        description = "dhcp pool start IP",
        default = "\"192.168.1.100\".to_string()"
    )]
    pool_start: String,

    #[argh(option, description = "dhcp pool end IP", default = "\"192.168.1.200\".to_string()")]
    pool_end: String,

    #[argh(option, description = "subnet mask", default = "\"255.255.255.0\".to_string()")]
    subnet_mask: String,

    #[argh(option, description = "default gateway", default = "\"192.168.1.1\".to_string()")]
    router: String,

    #[argh(option, description = "dns server", default = "\"8.8.8.8\".to_string()")]
    dns: String,

    //
    // Boot files
    //
    #[argh(
        option,
        short = 'b',
        description = "bios boot file",
        default = "\"pxelinux.0\".to_string()"
    )]
    bios: String,

    #[argh(
        option,
        short = 'e',
        description = "uefi boot file",
        default = "\"ipxe.efi\".to_string()"
    )]
    efi: String,
}

impl CliConfig {
    fn into_service_config(self) -> Result<ServiceConfig> {
        let tftp_ip: std::net::Ipv4Addr = self
            .ip
            .parse()
            .with_context(|| format!("Invalid TFTP server IP: {}", self.ip))?;

        let tftp_config = TftpServiceConfig {
            enabled: !self.disable_tftp,
            bind_address: self.tftp,
            root_directory: self.root,
            server_ip: tftp_ip,
        };

        let proxy_dhcp_config = ProxyDhcpServiceConfig {
            enabled: !self.disable_proxy_dhcp,
            bind_address: format!("{}:4011", self.proxy),
            tftp_server: tftp_ip,
            bios_bootfile: self.bios.clone(),
            efi_bootfile: self.efi.clone(),
        };

        let dhcp_config = DhcpServiceConfig {
            enabled: self.enable_dhcp,
            bind_address: self.dhcp,
            pool_start: self
                .pool_start
                .parse()
                .with_context(|| format!("Invalid DHCP pool start IP: {}", self.pool_start))?,
            pool_end: self
                .pool_end
                .parse()
                .with_context(|| format!("Invalid DHCP pool end IP: {}", self.pool_end))?,
            subnet_mask: self
                .subnet_mask
                .parse()
                .with_context(|| format!("Invalid subnet mask: {}", self.subnet_mask))?,
            router: self
                .router
                .parse()
                .with_context(|| format!("Invalid router IP: {}", self.router))?,
            dns_server: self
                .dns
                .parse()
                .with_context(|| format!("Invalid DNS server IP: {}", self.dns))?,
            tftp_server: tftp_ip,
            bios_bootfile: self.bios,
            efi_bootfile: self.efi,
        };

        Ok(ServiceConfig {
            interface: self.interface,
            tftp: tftp_config,
            proxy_dhcp: proxy_dhcp_config,
            dhcp: dhcp_config,
        })
    }
}

/// Trait for services that can be run
trait Service {
    fn name(&self) -> &'static str;
    fn run(self: Box<Self>) -> tokio::task::JoinHandle<Result<()>>;
}

/// Wrapper for TFTP service
struct TftpService {
    config: TftpServiceConfig,
}

impl Service for TftpService {
    fn name(&self) -> &'static str {
        "TFTP"
    }

    fn run(self: Box<Self>) -> tokio::task::JoinHandle<Result<()>> {
        let config = self.config;
        tokio::spawn(run_tftp_server(
            config.bind_address,
            config.root_directory,
            Some(IpAddr::V4(config.server_ip)),
        ))
    }
}

/// Wrapper for ProxyDHCP service
struct ProxyDhcpService {
    config: ProxyDhcpServiceConfig,
}

impl Service for ProxyDhcpService {
    fn name(&self) -> &'static str {
        "ProxyDHCP"
    }

    fn run(self: Box<Self>) -> tokio::task::JoinHandle<Result<()>> {
        let config = self.config;
        let proxy_config = ProxyConfig {
            bind: config.bind_address,
            tftp_server: config.tftp_server,
            bios_bootfile: config.bios_bootfile,
            efi_bootfile: config.efi_bootfile,
            server_identifier: Some(config.tftp_server),
        };
        tokio::spawn(async move { spawn_proxy_dhcp_server(proxy_config).await })
    }
}

/// Wrapper for DHCP service
struct DhcpService {
    config: DhcpServiceConfig,
}

impl Service for DhcpService {
    fn name(&self) -> &'static str {
        "DHCP"
    }

    fn run(self: Box<Self>) -> tokio::task::JoinHandle<Result<()>> {
        let config = self.config;
        let dhcp_config = DhcpConfig {
            bind: config.bind_address,
            pool_start: config.pool_start,
            pool_end: config.pool_end,
            subnet_mask: config.subnet_mask,
            router: config.router,
            dns_server: config.dns_server,
            domain_name: Some("local".to_string()),
            server_identifier: config.tftp_server,
            tftp_server: config.tftp_server,
            bios_bootfile: config.bios_bootfile,
            efi_bootfile: config.efi_bootfile,
            lease_time: 3600,
        };
        tokio::spawn(spawn_dhcp_server(dhcp_config))
    }
}

/// Service manager for handling multiple PXE services
pub struct ServiceManager {
    config: ServiceConfig,
}

impl ServiceManager {
    pub fn new(config: ServiceConfig) -> Result<Self> {
        // Validate network interface
        if_nametoindex(config.interface.as_str()).with_context(|| {
            format!(
                "Network interface '{}' not found. Please specify a valid network interface with --interface.",
                config.interface
            )
        })?;

        // Validate that at least one service is enabled
        if !config.tftp.enabled && !config.proxy_dhcp.enabled && !config.dhcp.enabled {
            return Err(anyhow::anyhow!("At least one service must be enabled"));
        }

        Ok(Self { config })
    }

    pub async fn run(self) -> Result<()> {
        let mut services: Vec<Box<dyn Service>> = Vec::new();
        let mut service_descriptions = Vec::new();

        // Add TFTP service if enabled
        if self.config.tftp.enabled {
            tracing::info!(
                "Starting TFTP server on {} with root: {}",
                self.config.tftp.bind_address,
                self.config.tftp.root_directory.display()
            );

            services.push(Box::new(TftpService {
                config: self.config.tftp.clone(),
            }));
            service_descriptions.push(format!("TFTP on {}", self.config.tftp.bind_address));
        }

        // Add ProxyDHCP service if enabled
        if self.config.proxy_dhcp.enabled {
            tracing::info!("Starting ProxyDHCP server on {}", self.config.proxy_dhcp.bind_address);

            services.push(Box::new(ProxyDhcpService {
                config: self.config.proxy_dhcp.clone(),
            }));
            service_descriptions.push(format!("ProxyDHCP on {}", self.config.proxy_dhcp.bind_address));
        }

        // Add DHCP service if enabled
        if self.config.dhcp.enabled {
            tracing::info!(
                "Starting DHCP server on {} (pool: {} - {})",
                self.config.dhcp.bind_address,
                self.config.dhcp.pool_start,
                self.config.dhcp.pool_end
            );

            services.push(Box::new(DhcpService {
                config: self.config.dhcp.clone(),
            }));
            service_descriptions.push(format!("DHCP on {}", self.config.dhcp.bind_address));
        }

        tracing::info!(
            "PXE server started on interface '{}' - {}",
            self.config.interface,
            service_descriptions.join(", ")
        );

        // Start all enabled services
        let mut tftp_handle = None;
        let mut proxy_handle = None;
        let mut dhcp_handle = None;

        for service in services {
            match service.name() {
                "TFTP" => tftp_handle = Some(service.run()),
                "ProxyDHCP" => proxy_handle = Some(service.run()),
                "DHCP" => dhcp_handle = Some(service.run()),
                svc => tracing::warn!("Unknown service: {svc}"),
            }
        }

        // Helper function to handle service completion results
        fn handle_service_result(
            name: &str,
            result: std::result::Result<Result<()>, tokio::task::JoinError>,
        ) -> Result<()> {
            match result {
                Ok(Ok(_)) => {
                    tracing::info!("{} service completed successfully", name);
                    Ok(())
                }
                Ok(Err(e)) => {
                    tracing::error!("{} service failed: {}", name, e);
                    Err(e)
                }
                Err(e) => {
                    tracing::error!("{} task panicked: {}", name, e);
                    Err(anyhow::anyhow!("{} task panicked: {}", name, e))
                }
            }
        }

        // Wait for any service to complete using biased select
        tokio::select! {
            biased;
            res = async { tftp_handle.as_mut().unwrap().await }, if tftp_handle.is_some() => {
                handle_service_result("TFTP", res)
            }
            res = async { proxy_handle.as_mut().unwrap().await }, if proxy_handle.is_some() => {
                handle_service_result("ProxyDHCP", res)
            }
            res = async { dhcp_handle.as_mut().unwrap().await }, if dhcp_handle.is_some() => {
                handle_service_result("DHCP", res)
            }
            else => {
                // No services enabled (should not happen due to validation)
                Err(anyhow::anyhow!("No services running"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli_config: CliConfig = argh::from_env();
    let service_config = cli_config.into_service_config()?;

    let service_manager = ServiceManager::new(service_config)?;
    service_manager.run().await
}
