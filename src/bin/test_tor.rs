use reqwest;
use std::time::Duration;

fn main() {
    println!("Testing tor proxy...");
    let url = "socks5h://127.0.0.1:9050";
    let proxy = reqwest::Proxy::all(url).unwrap();
    let client = reqwest::blocking::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    
    match client.get("https://api.ipify.org").send() {
        Ok(resp) => {
            println!("Status: {}", resp.status());
            println!("Body: {}", resp.text().unwrap());
        }
        Err(e) => {
            println!("Error: {:?}", e);
        }
    }
}
