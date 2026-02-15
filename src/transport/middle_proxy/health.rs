use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};
use rand::seq::SliceRandom;

use crate::crypto::SecureRandom;

use super::MePool;

pub async fn me_health_monitor(pool: Arc<MePool>, rng: Arc<SecureRandom>, _min_connections: usize) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        // Per-DC coverage check
        let map = pool.proxy_map_v4.read().await.clone();
        let writer_addrs: std::collections::HashSet<SocketAddr> = pool
            .writers
            .read()
            .await
            .iter()
            .map(|(a, _)| *a)
            .collect();

        for (dc, addrs) in map.iter() {
            let dc_addrs: Vec<SocketAddr> = addrs
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port))
                .collect();
            let has_coverage = dc_addrs.iter().any(|a| writer_addrs.contains(a));
            if !has_coverage {
                warn!(dc = %dc, "DC has no ME coverage, reconnecting...");
                let mut shuffled = dc_addrs.clone();
                shuffled.shuffle(&mut rand::rng());
                for addr in shuffled {
                    match pool.connect_one(addr, &rng).await {
                        Ok(()) => {
                            info!(%addr, dc = %dc, "ME reconnected for DC coverage");
                            break;
                        }
                        Err(e) => debug!(%addr, dc = %dc, error = %e, "ME reconnect failed"),
                    }
                }
            }
        }
    }
}
