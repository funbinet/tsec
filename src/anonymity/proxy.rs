//! Proxy pool manager — rotation, selection, and validation.

use std::collections::VecDeque;
use std::time::Instant;

/// Manages a rotating pool of proxy URLs.
pub struct ProxyManager {
    proxies: VecDeque<String>,
    rotation_secs: u64,
    last_rotated: Instant,
}

impl ProxyManager {
    /// Create a new proxy manager from a list of proxy URLs and rotation interval.
    pub fn new(proxies: Vec<String>, rotation_secs: u64) -> Self {
        Self {
            proxies: proxies.into(),
            rotation_secs,
            last_rotated: Instant::now(),
        }
    }

    /// Returns the current (front) proxy URL, or `None` if the pool is empty.
    pub fn get_current(&self) -> Option<&str> {
        self.proxies.front().map(|s| s.as_str())
    }

    /// Rotate the pool: move the front proxy to the back.
    pub fn rotate(&mut self) {
        if self.proxies.len() > 1 {
            self.proxies.rotate_left(1);
            self.last_rotated = Instant::now();
        }
    }

    /// Automatically rotate if the configured interval has elapsed.
    /// Returns `true` if rotation occurred.
    pub fn auto_rotate_if_needed(&mut self) -> bool {
        if self.rotation_secs == 0 || self.proxies.len() <= 1 {
            return false;
        }
        if self.last_rotated.elapsed().as_secs() >= self.rotation_secs {
            self.rotate();
            true
        } else {
            false
        }
    }

    /// Select a random proxy from the pool (does not rotate).
    pub fn random_proxy(&self) -> Option<&str> {
        if self.proxies.is_empty() {
            return None;
        }
        use rand::Rng;
        let idx = rand::thread_rng().gen_range(0..self.proxies.len());
        Some(&self.proxies[idx])
    }

    /// Test if a proxy is reachable by attempting a TCP connection.
    pub fn validate_proxy(addr: &str) -> bool {
        // Strip the scheme prefix to get host:port
        let host_port = addr
            .trim_start_matches("socks5://")
            .trim_start_matches("socks5h://")
            .trim_start_matches("socks4://")
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        std::net::TcpStream::connect_timeout(
            &host_port.parse().unwrap_or_else(|_| {
                std::net::SocketAddr::from(([127, 0, 0, 1], 0))
            }),
            std::time::Duration::from_secs(5),
        )
        .is_ok()
    }

    /// Returns the number of proxies in the pool.
    pub fn count(&self) -> usize {
        self.proxies.len()
    }

    /// Returns `true` if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Add a proxy to the pool.
    pub fn add(&mut self, proxy: String) {
        self.proxies.push_back(proxy);
    }

    /// Remove a proxy by index.
    pub fn remove(&mut self, idx: usize) -> Option<String> {
        self.proxies.remove(idx)
    }

    /// Get all proxies as a slice-like view.
    pub fn list(&self) -> Vec<&str> {
        self.proxies.iter().map(|s| s.as_str()).collect()
    }
}
