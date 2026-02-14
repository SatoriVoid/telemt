use std::net::{IpAddr, Ipv4Addr};

use tracing::{info, warn};

use crate::error::{ProxyError, Result};

use super::MePool;

impl MePool {
    pub(super) fn translate_ip_for_nat(&self, ip: IpAddr) -> IpAddr {
        let nat_ip = self
            .nat_ip_cfg
            .or_else(|| self.nat_ip_detected.get().copied());

        let Some(nat_ip) = nat_ip else {
            return ip;
        };

        match (ip, nat_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if is_privateish(IpAddr::V4(src))
                    || src.is_loopback()
                    || src.is_unspecified() =>
            {
                IpAddr::V4(dst)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) if src.is_loopback() || src.is_unspecified() => {
                IpAddr::V6(dst)
            }
            (orig, _) => orig,
        }
    }

    pub(super) async fn maybe_detect_nat_ip(&self, local_ip: IpAddr) -> Option<IpAddr> {
        if self.nat_ip_cfg.is_some() {
            return self.nat_ip_cfg;
        }

        if !(is_privateish(local_ip) || local_ip.is_loopback() || local_ip.is_unspecified()) {
            return None;
        }

        if let Some(ip) = self.nat_ip_detected.get().copied() {
            return Some(ip);
        }

        match fetch_public_ipv4().await {
            Ok(Some(ip)) => {
                let _ = self.nat_ip_detected.set(IpAddr::V4(ip));
                info!(public_ip = %ip, "Auto-detected public IP for NAT translation");
                Some(IpAddr::V4(ip))
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "Failed to auto-detect public IP");
                None
            }
        }
    }
}

async fn fetch_public_ipv4() -> Result<Option<Ipv4Addr>> {
    let res = reqwest::get("https://checkip.amazonaws.com").await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection request failed: {e}"))
    })?;

    let text = res.text().await.map_err(|e| {
        ProxyError::Proxy(format!("public IP detection read failed: {e}"))
    })?;

    let ip = text.trim().parse().ok();
    Ok(ip)
}

fn is_privateish(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}
