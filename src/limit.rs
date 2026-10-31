//! Per-client connection cap.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Counts open connections per client address.
#[derive(Clone)]
pub struct ConnLimiter {
	max: usize,
	open: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// Held while a connection is open. Releases its slot on drop.
pub struct Slot {
	ip: IpAddr,
	open: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl ConnLimiter {
	/// Allows at most `max` simultaneous connections per address.
	pub fn new(max: usize) -> Self {
		Self {
			max,
			open: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	/// Takes a slot for `ip`, or `None` if the address is at its limit.
	pub fn acquire(&self, ip: IpAddr) -> Option<Slot> {
		let mut open = self
			.open
			.lock()
			.expect("limiter lock is never held across a panic");
		let n = open.entry(ip).or_insert(0);
		if *n >= self.max {
			return None;
		}
		*n += 1;
		Some(Slot {
			ip,
			open: self.open.clone(),
		})
	}

	/// Number of addresses with at least one open connection.
	pub fn clients(&self) -> usize {
		self.open
			.lock()
			.expect("limiter lock is never held across a panic")
			.len()
	}
}

impl Drop for Slot {
	fn drop(&mut self) {
		let mut open = self
			.open
			.lock()
			.expect("limiter lock is never held across a panic");
		let count = open.entry(self.ip).or_insert(1);
		*count -= 1;
		if *count == 0 {
			open.remove(&self.ip);
		}
	}
}
