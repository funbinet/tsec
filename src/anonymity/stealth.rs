//! Stealth features — User-Agent rotation, MAC spoofing, hostname spoofing.

use rand::seq::SliceRandom;

// ── User-Agent pool ────────────────────────────────────────────────────

/// A pool of realistic, modern browser User-Agent strings.
static USER_AGENTS: &[&str] = &[
    // Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    // Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    // Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    // Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    // Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    // Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    // Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    // Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    // Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    // Brave (looks like Chrome)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    // Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    // Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
];

/// Return a random User-Agent string from the pool.
pub fn random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0])
}

// ── MAC spoofing ───────────────────────────────────────────────────────

/// Spoof the MAC address on the given network interface using `macchanger`.
/// Returns the original MAC for later restoration.
/// Requires root privileges.
pub fn spoof_mac(interface: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Get the current MAC first
    let output = std::process::Command::new("macchanger")
        .args(["--show", interface])
        .output()?;
    let show_output = String::from_utf8_lossy(&output.stdout);
    let original_mac = show_output
        .lines()
        .find(|l| l.contains("Current MAC"))
        .and_then(|l| l.split_whitespace().nth(2)) // 0: Current, 1: MAC:, 2: <MAC>
        .unwrap_or("unknown")
        .to_string();

    // Bring interface down
    std::process::Command::new("ip")
        .args(["link", "set", interface, "down"])
        .status()?;

    // Randomize MAC
    let result = std::process::Command::new("macchanger")
        .args(["--random", interface])
        .output()?;

    // Bring interface back up
    std::process::Command::new("ip")
        .args(["link", "set", interface, "up"])
        .status()?;

    if !result.status.success() {
        return Err(format!(
            "macchanger failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ).into());
    }

    Ok(original_mac)
}

/// Restore a previously saved MAC address.
pub fn restore_mac(interface: &str, original_mac: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::process::Command::new("ip")
        .args(["link", "set", interface, "down"])
        .status()?;

    std::process::Command::new("macchanger")
        .args(["--mac", original_mac, interface])
        .status()?;

    std::process::Command::new("ip")
        .args(["link", "set", interface, "up"])
        .status()?;

    Ok(())
}

/// Detect the default network interface name.
pub fn default_interface() -> Option<String> {
    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse: "default via X.X.X.X dev <interface> ..."
    text.split_whitespace()
        .skip_while(|w| *w != "dev")
        .nth(1)
        .map(|s| s.to_string())
}

// ── Hostname spoofing ──────────────────────────────────────────────────

/// Generate a random hostname and set it via the `hostname` command.
/// Returns the original hostname for later restoration.
pub fn spoof_hostname() -> Result<String, Box<dyn std::error::Error>> {
    // Save original
    let original = hostname::get()?
        .to_string_lossy()
        .into_owned();

    // Generate random hostname
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let names = ["desktop", "laptop", "workstation", "pc", "host", "node", "srv", "box"];
    let prefix = names.choose(&mut rng).unwrap_or(&"host");
    let suffix: u32 = rng.gen_range(1000..9999);
    let new_hostname = format!("{}-{}", prefix, suffix);

    std::process::Command::new("hostname")
        .arg(&new_hostname)
        .status()?;

    Ok(original)
}

/// Restore the original hostname.
pub fn restore_hostname(original: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::process::Command::new("hostname")
        .arg(original)
        .status()?;
    Ok(())
}

/// Check if `macchanger` is available on the system.
pub fn macchanger_available() -> bool {
    std::process::Command::new("which")
        .arg("macchanger")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check if `proxychains4` is available on the system.
pub fn proxychains_available() -> bool {
    std::process::Command::new("which")
        .arg("proxychains4")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
