//! Destination policy: where the bridge may connect. This is the SSRF defence.
//!
//! Rules:
//! - Ports: only 22 unless the operator adds more, explicitly.
//! - Addresses: only global unicast. Private, loopback, link-local, CGNAT, multicast,
//!   reserved, documentation and cloud metadata ranges are denied, for IPv4 and IPv6.
//! - IPv6 forms that embed an IPv4 address (mapped, compatible, NAT64, 6to4) are judged by the
//!   embedded IPv4 address.
//! - Hostnames are resolved by us, every resulting address must pass, and the connection goes
//!   to the checked address, never to the name again (DNS rebinding).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The default allowed port.
pub const DEFAULT_PORT: u16 = 22;

/// Why a destination was refused. Details stay server side and are not sent to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
	/// The host string is empty, too long, or has characters a host name cannot have.
	InvalidHost,
	/// The port is not on the allow list.
	Port,
	/// At least one resolved address is in a forbidden range.
	Address,
	/// The name did not resolve to any address.
	NoAddress,
}

/// Forbidden IPv4 ranges as (network, prefix length).
const V4_FORBIDDEN: &[(Ipv4Addr, u8)] = &[
	(Ipv4Addr::new(0, 0, 0, 0), 8),        // "this network"
	(Ipv4Addr::new(10, 0, 0, 0), 8),       // private
	(Ipv4Addr::new(100, 64, 0, 0), 10),    // CGNAT, includes Alibaba metadata 100.100.100.200
	(Ipv4Addr::new(127, 0, 0, 0), 8),      // loopback
	(Ipv4Addr::new(168, 63, 129, 16), 32), // Azure wire server
	(Ipv4Addr::new(169, 254, 0, 0), 16),   // link-local, AWS/GCP/Azure metadata, ECS
	(Ipv4Addr::new(172, 16, 0, 0), 12),    // private
	(Ipv4Addr::new(192, 0, 0, 0), 24),     // IETF assignments, Oracle metadata 192.0.0.192
	(Ipv4Addr::new(192, 0, 2, 0), 24),     // documentation
	(Ipv4Addr::new(192, 31, 196, 0), 24),  // AS112
	(Ipv4Addr::new(192, 52, 193, 0), 24),  // AMT
	(Ipv4Addr::new(192, 88, 99, 0), 24),   // 6to4 relay anycast
	(Ipv4Addr::new(192, 168, 0, 0), 16),   // private
	(Ipv4Addr::new(192, 175, 48, 0), 24),  // AS112
	(Ipv4Addr::new(198, 18, 0, 0), 15),    // benchmarking
	(Ipv4Addr::new(198, 51, 100, 0), 24),  // documentation
	(Ipv4Addr::new(203, 0, 113, 0), 24),   // documentation
	(Ipv4Addr::new(224, 0, 0, 0), 4),      // multicast
	(Ipv4Addr::new(240, 0, 0, 0), 4),      // reserved, includes broadcast
];

fn v4_forbidden(ip: Ipv4Addr) -> bool {
	let n = u32::from(ip);
	V4_FORBIDDEN.iter().any(|(net, prefix)| {
		let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
		n & mask == u32::from(*net)
	})
}

fn v6_forbidden(ip: Ipv6Addr) -> bool {
	// ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible), which also catches :: and ::1.
	if let Some(v4) = ip.to_ipv4() {
		return v4_forbidden(v4);
	}
	let s = ip.segments();
	let embedded = |hi: u16, lo: u16| {
		let [a, b] = hi.to_be_bytes();
		let [c, d] = lo.to_be_bytes();
		v4_forbidden(Ipv4Addr::new(a, b, c, d))
	};
	// 64:ff9b::/96 NAT64: judged by the IPv4 address in the low 32 bits.
	if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|x| *x == 0) {
		return embedded(s[6], s[7]);
	}
	// 2002::/16 6to4: judged by the IPv4 address in bits 16..48.
	if s[0] == 0x2002 {
		return embedded(s[1], s[2]);
	}
	// Only 2000::/3 is global unicast. Everything else (unspecified, loopback, ULA fc00::/7,
	// link-local fe80::/10, site-local, multicast ff00::/8, SIIT, local NAT64, SRv6) is out.
	if s[0] & 0xe000 != 0x2000 {
		return true;
	}
	// 2001::/23 IETF protocol assignments (Teredo, benchmarking, ORCHID), 2001:db8::/32
	// documentation, 3fff::/20 documentation.
	(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8)) || (s[0] == 0x3fff && s[1] < 0x1000)
}

/// Returns whether an address must never be dialled.
pub fn is_forbidden(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(v4) => v4_forbidden(v4),
		IpAddr::V6(v6) => v6_forbidden(v6),
	}
}

/// Checks that a host string is a plausible DNS name or IP literal.
fn valid_host(host: &str) -> bool {
	let host = host.strip_suffix('.').unwrap_or(host);
	if host.is_empty() || host.len() > 253 {
		return false;
	}
	if host.contains(':') {
		return host.parse::<Ipv6Addr>().is_ok();
	}
	host.split('.').all(|label| {
		!label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with('-')
			&& !label.ends_with('-')
			&& label
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
	})
}

/// Which destinations the bridge allows.
#[derive(Debug, Clone)]
pub struct Policy {
	ports: BTreeSet<u16>,
	allow_any_address: bool,
}

impl Policy {
	/// Port 22 plus the operator's explicit `extra_ports`. Port 0 is never allowed.
	pub fn new(extra_ports: &[u16]) -> Self {
		let mut ports: BTreeSet<u16> = extra_ports.iter().copied().filter(|p| *p != 0).collect();
		ports.insert(DEFAULT_PORT);
		Self {
			ports,
			allow_any_address: false,
		}
	}

	/// Skips the address check so tests can dial loopback. Not available in release builds
	/// of the binary.
	#[cfg(feature = "test-support")]
	pub fn allow_any_address(mut self) -> Self {
		self.allow_any_address = true;
		self
	}

	/// Checks the port alone.
	pub fn check_port(&self, port: u16) -> Result<(), Denied> {
		if self.ports.contains(&port) {
			Ok(())
		} else {
			Err(Denied::Port)
		}
	}

	/// Checks a host, port and the addresses it resolved to. Every address must pass.
	/// Returns the addresses to dial.
	pub fn vet(
		&self,
		host: &str,
		port: u16,
		resolved: &[IpAddr],
	) -> Result<Vec<SocketAddr>, Denied> {
		if !valid_host(host) {
			return Err(Denied::InvalidHost);
		}
		self.check_port(port)?;
		if resolved.is_empty() {
			return Err(Denied::NoAddress);
		}
		if !self.allow_any_address && resolved.iter().any(|ip| is_forbidden(*ip)) {
			return Err(Denied::Address);
		}
		Ok(resolved
			.iter()
			.map(|ip| SocketAddr::new(*ip, port))
			.collect())
	}

	/// Resolves `host` ourselves and vets the result. IP literals are not looked up.
	pub async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, Denied> {
		if !valid_host(host) {
			return Err(Denied::InvalidHost);
		}
		self.check_port(port)?;
		let bare = host.strip_suffix('.').unwrap_or(host);
		let ips: Vec<IpAddr> = match bare.parse::<IpAddr>() {
			Ok(ip) => vec![ip],
			Err(_) => match tokio::net::lookup_host((bare, port)).await {
				Ok(found) => found.map(|a| a.ip()).collect(),
				Err(_) => Vec::new(),
			},
		};
		self.vet(host, port, &ips)
	}
}
