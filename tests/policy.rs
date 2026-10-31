//! Adversarial tests for the destination policy.

use kabuk_bridge::policy::{Denied, Policy, is_forbidden};
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
	s.parse().unwrap_or_else(|_| panic!("bad test address {s}"))
}

fn denied(s: &str) {
	assert!(is_forbidden(ip(s)), "{s} must be forbidden");
}

fn allowed(s: &str) {
	assert!(!is_forbidden(ip(s)), "{s} must be allowed");
}

#[test]
fn ipv4_private_loopback_linklocal_cgnat_multicast_reserved() {
	for s in [
		"0.0.0.0",
		"0.255.255.255",
		"10.0.0.0",
		"10.255.255.255",
		"100.64.0.0",
		"100.127.255.255",
		"127.0.0.1",
		"127.255.255.255",
		"169.254.0.0",
		"169.254.255.255",
		"172.16.0.0",
		"172.31.255.255",
		"192.0.0.0",
		"192.0.0.255",
		"192.0.2.1",
		"192.168.0.0",
		"192.168.255.255",
		"198.18.0.0",
		"198.19.255.255",
		"198.51.100.7",
		"203.0.113.7",
		"224.0.0.0",
		"239.255.255.255",
		"240.0.0.0",
		"255.255.255.255",
		"192.88.99.1",
		"192.31.196.1",
		"192.52.193.1",
		"192.175.48.1",
	] {
		denied(s);
	}
}

#[test]
fn ipv4_neighbours_of_forbidden_ranges_are_allowed() {
	for s in [
		"1.0.0.0",
		"9.255.255.255",
		"11.0.0.0",
		"100.63.255.255",
		"100.128.0.0",
		"126.255.255.255",
		"128.0.0.0",
		"169.253.255.255",
		"169.255.0.0",
		"172.15.255.255",
		"172.32.0.0",
		"192.0.1.0",
		"192.0.3.0",
		"192.167.255.255",
		"192.169.0.0",
		"198.17.255.255",
		"198.20.0.0",
		"198.51.99.255",
		"198.51.101.0",
		"203.0.112.255",
		"203.0.114.0",
		"223.255.255.255",
		"8.8.8.8",
		"93.184.216.34",
		"168.63.129.15",
		"168.63.129.17",
	] {
		allowed(s);
	}
}

#[test]
fn cloud_metadata_addresses() {
	for s in [
		"169.254.169.254", // AWS, GCP, Azure, DigitalOcean, OpenStack
		"169.254.170.2",   // AWS ECS task metadata
		"168.63.129.16",   // Azure wire server
		"100.100.100.200", // Alibaba
		"192.0.0.192",     // Oracle
		"fd00:ec2::254",   // AWS IPv6
		"fd20:ce::254",    // GCP IPv6 style ULA
		"::ffff:169.254.169.254",
		"::ffff:a9fe:a9fe",
	] {
		denied(s);
	}
}

#[test]
fn ipv6_special_ranges() {
	for s in [
		"::",
		"::1",
		"fe80::1",
		"febf::1",
		"fc00::1",
		"fdff::1",
		"fec0::1",
		"ff02::1",
		"ff0e::1",
		"2001:db8::1",
		"2001::1",
		"2001:1ff::1",
		"2001:2::1",
		"3fff::1",
		"3fff:fff::1",
		"100::1",
		"5f00::1",
		"1::1",
		"4000::1",
		"64:ff9b:1::1",
		"::ffff:0:7f00:1",
	] {
		denied(s);
	}
}

#[test]
fn ipv6_global_unicast_is_allowed() {
	for s in [
		"2001:200::1",
		"2001:4860:4860::8888",
		"2606:4700:4700::1111",
		"2a00:1450:4001::1",
		"3ffe::1",
		"3fff:1000::1",
	] {
		allowed(s);
	}
}

#[test]
fn ipv4_mapped_and_compatible_tricks() {
	for s in [
		"::ffff:127.0.0.1",
		"::ffff:7f00:1",
		"::ffff:10.0.0.1",
		"::ffff:192.168.1.1",
		"::ffff:0.0.0.0",
		"::ffff:100.64.0.1",
		"::ffff:224.0.0.1",
		"::127.0.0.1",
		"::7f00:1",
		"::10.0.0.1",
		"0:0:0:0:0:ffff:7f00:1",
		"0000:0000:0000:0000:0000:ffff:127.0.0.1",
	] {
		denied(s);
	}
	allowed("::ffff:8.8.8.8");
	allowed("::ffff:93.184.216.34");
}

#[test]
fn nat64_and_6to4_embed_ipv4() {
	denied("64:ff9b::7f00:1");
	denied("64:ff9b::a00:1");
	denied("64:ff9b::a9fe:a9fe");
	allowed("64:ff9b::808:808");
	denied("2002:7f00:1::1");
	denied("2002:a00:1::");
	denied("2002:c0a8:101::1");
	denied("2002:a9fe:a9fe::1");
	allowed("2002:808:808::1");
}

#[test]
fn every_slash16_agrees_with_an_independent_reference() {
	// Reference: ranges written as plain (first, last) integer pairs, a different shape from the
	// implementation's network and prefix table.
	const RANGES: &[(u32, u32)] = &[
		(0x0000_0000, 0x00ff_ffff),
		(0x0a00_0000, 0x0aff_ffff),
		(0x6440_0000, 0x647f_ffff),
		(0x7f00_0000, 0x7fff_ffff),
		(0xa9fe_0000, 0xa9fe_ffff),
		(0xac10_0000, 0xac1f_ffff),
		(0xc000_0000, 0xc000_00ff),
		(0xc000_0200, 0xc000_02ff),
		(0xc01f_c400, 0xc01f_c4ff),
		(0xc034_c100, 0xc034_c1ff),
		(0xc058_6300, 0xc058_63ff),
		(0xc0a8_0000, 0xc0a8_ffff),
		(0xc0af_3000, 0xc0af_30ff),
		(0xc612_0000, 0xc613_ffff),
		(0xc633_6400, 0xc633_64ff),
		(0xcb00_7100, 0xcb00_71ff),
		(0xe000_0000, 0xffff_ffff),
	];
	for hi in 0..=0xffffu32 {
		for lo in [0u32, 0x1, 0x7fff, 0xff00, 0xffff] {
			let n = (hi << 16) | lo;
			let expected = RANGES.iter().any(|(a, b)| (*a..=*b).contains(&n));
			let got = is_forbidden(IpAddr::from(std::net::Ipv4Addr::from(n)));
			assert_eq!(got, expected, "{}", std::net::Ipv4Addr::from(n));
		}
	}
}

#[test]
fn ports_default_22_only() {
	let p = Policy::new(&[]);
	assert_eq!(p.check_port(22), Ok(()));
	for port in [0u16, 1, 21, 23, 80, 443, 2222, 65535] {
		assert_eq!(p.check_port(port), Err(Denied::Port), "port {port}");
	}
}

#[test]
fn extra_ports_are_explicit_and_zero_is_never_allowed() {
	let p = Policy::new(&[2222, 0]);
	assert_eq!(p.check_port(22), Ok(()));
	assert_eq!(p.check_port(2222), Ok(()));
	assert_eq!(p.check_port(0), Err(Denied::Port));
	assert_eq!(p.check_port(2223), Err(Denied::Port));
}

#[test]
fn vet_requires_every_resolved_address_to_pass() {
	let p = Policy::new(&[]);
	let public = ip("93.184.216.34");
	let got = p
		.vet("example.com", 22, &[public, ip("2606:4700::1")])
		.unwrap();
	assert_eq!(got.len(), 2);
	assert!(got.iter().all(|a| a.port() == 22));
	// A rebinding style answer: one public address plus one internal address is refused whole.
	assert_eq!(
		p.vet("evil.example", 22, &[public, ip("127.0.0.1")]),
		Err(Denied::Address)
	);
	assert_eq!(
		p.vet("evil.example", 22, &[ip("10.0.0.5"), public]),
		Err(Denied::Address)
	);
	assert_eq!(
		p.vet("evil.example", 22, &[ip("::ffff:127.0.0.1")]),
		Err(Denied::Address)
	);
	assert_eq!(p.vet("example.com", 22, &[]), Err(Denied::NoAddress));
	assert_eq!(p.vet("example.com", 80, &[public]), Err(Denied::Port));
}

#[test]
fn hostile_host_strings_are_rejected() {
	let p = Policy::new(&[]);
	let long_label = "a".repeat(64);
	let long_name = format!("{}.com", "a.".repeat(130));
	for h in [
		"",
		".",
		"..",
		"a..b",
		"-",
		"host name",
		"host\0",
		"host\n",
		"a/b",
		"a@b",
		"a#b",
		"a?b",
		"a:b",
		"[::1]",
		"fe80::1%eth0",
		"例え.jp",
		"%31%32%37.0.0.1",
		"a.b.c.d\u{3002}e",
		&long_label,
		&long_name,
		"1:2:3",
	] {
		assert_eq!(
			p.vet(h, 22, &[ip("93.184.216.34")]),
			Err(Denied::InvalidHost),
			"{h:?}"
		);
	}
}

#[test]
fn plausible_hosts_pass_validation() {
	let p = Policy::new(&[]);
	let a = [ip("93.184.216.34")];
	for h in [
		"example.com",
		"example.com.",
		"a-b.example",
		"xn--bcher-kva.example",
		"_srv.example",
		"host1",
		"93.184.216.34",
		"2606:4700::1",
	] {
		assert!(p.vet(h, 22, &a).is_ok(), "{h}");
	}
}

#[tokio::test]
async fn resolve_denies_numeric_tricks_that_the_system_resolver_may_expand() {
	let p = Policy::new(&[]);
	// getaddrinfo may expand these to 127.0.0.1 or 0.0.0.0; either way they are denied or fail to resolve.
	for h in [
		"127.1",
		"2130706433",
		"0x7f.1",
		"0177.0.0.1",
		"0",
		"localhost",
		"0.0.0.0",
		"127.0.0.1",
		"::1",
		"::ffff:127.0.0.1",
		"169.254.169.254",
		"10.0.0.1",
	] {
		assert!(p.resolve(h, 22).await.is_err(), "{h}");
	}
}

#[tokio::test]
async fn resolve_checks_port_and_host_before_any_lookup() {
	let p = Policy::new(&[]);
	assert_eq!(p.resolve("93.184.216.34", 80).await, Err(Denied::Port));
	assert_eq!(p.resolve("bad host", 22).await, Err(Denied::InvalidHost));
}

#[tokio::test]
async fn resolve_accepts_public_literals_without_dns() {
	let p = Policy::new(&[]);
	assert_eq!(
		p.resolve("93.184.216.34", 22).await.unwrap(),
		vec!["93.184.216.34:22".parse().unwrap()]
	);
	assert_eq!(p.resolve("93.184.216.34.", 22).await.unwrap().len(), 1);
	assert_eq!(
		p.resolve("2606:4700:4700::1111", 22).await.unwrap().len(),
		1
	);
}

#[tokio::test]
async fn unresolvable_name_is_refused() {
	let p = Policy::new(&[]);
	// The reserved .invalid TLD never resolves (RFC 6761).
	assert_eq!(
		p.resolve("nothing.invalid", 22).await,
		Err(Denied::NoAddress)
	);
}
