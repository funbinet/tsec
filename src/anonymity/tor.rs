//! Tor integration — service detection, exit IP verification, circuit renewal.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::sync::RwLock;
use lazy_static::lazy_static;

lazy_static! {
    static ref CACHED_TOR_IP: RwLock<String> = RwLock::new("Resolving...".to_string());
}

/// Manages Tor SOCKS5 proxy connectivity.
pub struct TorManager {
    socks_addr: String,
}

impl TorManager {
    /// Create a new Tor manager pointing at the given SOCKS5 address.
    pub fn new(socks_addr: &str) -> Self {
        Self {
            socks_addr: socks_addr.to_string(),
        }
    }

    /// Returns the configured SOCKS5 address (e.g. "127.0.0.1:9050").
    pub fn socks_addr(&self) -> &str {
        &self.socks_addr
    }

    /// Returns the full SOCKS5 URL suitable for proxy env vars.
    pub fn socks_url(&self) -> String {
        format!("socks5h://{}", self.socks_addr)
    }

    /// Check if the Tor SOCKS port is accepting connections.
    pub fn is_running(&self) -> bool {
        TcpStream::connect_timeout(
            &self.socks_addr.parse().unwrap_or_else(|_| {
                std::net::SocketAddr::from(([127, 0, 0, 1], 9050))
            }),
            Duration::from_secs(3),
        )
        .is_ok()
    }

    /// Fetch the current Tor exit IP via the Tor check API.
    /// Routes the request through the Tor SOCKS proxy.
    pub fn get_exit_ip(&self) -> Result<String, Box<dyn std::error::Error>> {
        let proxy = reqwest::Proxy::all(&self.socks_url())?;
        let client = reqwest::blocking::Client::builder()
            .proxy(proxy)
            .timeout(Duration::from_secs(10))
            .build()?;
        let resp = client.get("https://api.ipify.org").send()?;
        Ok(resp.text()?.trim().to_string())
    }

    /// Fetch the exit IP and update the global cache.
    pub fn update_cached_ip(&self) {
        if let Ok(ip) = self.get_exit_ip() {
            if let Ok(mut cache) = CACHED_TOR_IP.write() {
                *cache = ip;
            }
        }
    }

    /// Read the currently cached Tor IP without blocking.
    pub fn get_cached_ip() -> String {
        CACHED_TOR_IP.read().map(|c| c.clone()).unwrap_or_else(|_| "Resolving...".to_string())
    }

    /// Request a new Tor circuit via the control port (9051).
    /// This changes the exit node for subsequent connections.
    /// Requires `CookieAuthentication` or `HashedControlPassword` in torrc.
    pub fn new_circuit(&self) -> Result<(), Box<dyn std::error::Error>> {
        let control_addr = self.socks_addr.replace(":9050", ":9051");
        let addr: std::net::SocketAddr = control_addr.parse().unwrap_or_else(|_| {
            std::net::SocketAddr::from(([127, 0, 0, 1], 9051))
        });

        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;

        // Authenticate (assumes no password / cookie auth)
        stream.write_all(b"AUTHENTICATE\r\n")?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf)?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.starts_with("250") {
            return Err(format!("Tor auth failed: {}", response.trim()).into());
        }

        // Signal NEWNYM for new circuit
        stream.write_all(b"SIGNAL NEWNYM\r\n")?;
        let n = stream.read(&mut buf)?;
        let response = String::from_utf8_lossy(&buf[..n]);
        if !response.starts_with("250") {
            return Err(format!("Tor NEWNYM failed: {}", response.trim()).into());
        }

        // Give Tor a moment to build the new circuit
        std::thread::sleep(Duration::from_secs(2));
        Ok(())
    }
}
