use std::io::{Error, ErrorKind, Result};
use std::net::Ipv4Addr;

use nix::ifaddrs::getifaddrs;

pub fn get_interface_ip(name: &str) -> Result<Ipv4Addr> {
    getifaddrs()?
        .find_map(|ifa| {
            if ifa.interface_name != name {
                return None;
            }
            ifa.address.and_then(|addr| addr.as_sockaddr_in().map(|sin| sin.ip()))
        })
        .ok_or_else(|| Error::from(ErrorKind::NotFound))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ip() -> Result<()> {
        #[cfg(target_os = "macos")]
        let name = "lo0";
        #[cfg(not(target_os = "macos"))]
        let name = "lo";

        let ip = get_interface_ip(name)?;
        assert!(ip.is_loopback());

        Ok(())
    }
}
