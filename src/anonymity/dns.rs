//! DNS-over-HTTPS resolver — prevents DNS leaks by routing queries through
//! Cloudflare's DoH endpoint instead of the system resolver.

use std::time::Duration;

/// Resolve a domain name to IP addresses via Cloudflare DNS-over-HTTPS.
/// This prevents the system resolver (and ISP) from seeing DNS queries.
pub fn resolve_doh(domain: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://1.1.1.1/dns-query?name={}&type=A",
        domain
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let resp = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .send()?;

    let body: serde_json::Value = resp.json()?;

    let mut ips = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(|a| a.as_array()) {
        for answer in answers {
            // Type 1 = A record, Type 28 = AAAA record
            if let (Some(data), Some(rtype)) = (
                answer.get("data").and_then(|d| d.as_str()),
                answer.get("type").and_then(|t| t.as_u64()),
            ) {
                if rtype == 1 || rtype == 28 {
                    ips.push(data.to_string());
                }
            }
        }
    }

    Ok(ips)
}

/// Check if DNS-over-HTTPS is reachable by resolving a known domain.
pub fn doh_available() -> bool {
    resolve_doh("cloudflare.com").map(|ips| !ips.is_empty()).unwrap_or(false)
}
