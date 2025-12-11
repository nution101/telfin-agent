// Network awareness module for self-healing
//
// Provides functions to detect network availability and wait for
// connectivity before attempting reconnections. This prevents the
// agent from spinning in tight retry loops when the network is down.

use std::net::TcpStream;
use std::time::Duration;

/// Default gateway host to check for connectivity
const DEFAULT_GATEWAY_HOST: &str = "gateway.telfin.io";

/// Check if we can reach a host on port 443 (HTTPS)
pub fn can_reach_host(host: &str) -> bool {
    let addr = format!("{}:443", host);
    match addr.parse() {
        Ok(socket_addr) => {
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(5)).is_ok()
        }
        Err(_) => {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            match format!("{}:443", host).to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).is_ok()
                    } else {
                        false
                    }
                }
                Err(_) => false,
            }
        }
    }
}

/// Check if we can reach the default gateway
pub fn can_reach_gateway() -> bool {
    can_reach_host(DEFAULT_GATEWAY_HOST)
}

/// Wait for network to become available with exponential backoff
/// 
/// Returns true if network became available, false if max_wait elapsed
pub async fn wait_for_network(host: &str, max_wait: Duration) -> bool {
    let mut backoff = Duration::from_secs(2);
    let max_backoff = Duration::from_secs(30);
    let start = std::time::Instant::now();
    
    tracing::info!("Waiting for network connectivity to {}...", host);
    
    while start.elapsed() < max_wait {
        if can_reach_host(host) {
            tracing::info!("Network connectivity restored after {:?}", start.elapsed());
            return true;
        }
        
        tracing::debug!("Network unreachable, retrying in {:?}...", backoff);
        tokio::time::sleep(backoff).await;
        
        // Exponential backoff with jitter
        let jitter = Duration::from_millis(rand::random::<u64>() % 1000);
        backoff = (backoff * 2).min(max_backoff) + jitter;
    }
    
    tracing::warn!("Network wait timed out after {:?}", max_wait);
    false
}

/// Extract host from a server URL
pub fn extract_host(server_url: &str) -> Option<String> {
    url::Url::parse(server_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host() {
        assert_eq!(
            extract_host("https://gateway.telfin.io"),
            Some("gateway.telfin.io".to_string())
        );
        assert_eq!(
            extract_host("https://gateway.telfin.io:443/api"),
            Some("gateway.telfin.io".to_string())
        );
        assert_eq!(extract_host("not-a-url"), None);
    }
}
