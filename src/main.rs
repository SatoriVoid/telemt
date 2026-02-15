//! telemt — Telegram MTProto Proxy

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, prelude::*, reload};

mod cli;
mod config;
mod crypto;
mod error;
mod ip_tracker;
mod protocol;
mod proxy;
mod stats;
mod stream;
mod transport;
mod util;

use crate::config::{ProxyConfig, LogLevel};
use crate::proxy::{ClientHandler, handle_client_stream};
#[cfg(unix)]
use crate::transport::{create_unix_listener, cleanup_unix_socket};
use crate::crypto::SecureRandom;
use crate::ip_tracker::UserIpTracker;
use crate::stats::{ReplayChecker, Stats};
use crate::stream::BufferPool;
use crate::transport::middle_proxy::MePool;
use crate::transport::{ListenOptions, UpstreamManager, create_listener};
use crate::util::ip::detect_ip;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {

    let config = Arc::new(ProxyConfig::load("config.toml")?);
    let stats = Arc::new(Stats::new());
    let rng = Arc::new(SecureRandom::new());

    let replay_checker = Arc::new(ReplayChecker::new(
        config.access.replay_check_len,
        Duration::from_secs(config.access.replay_window_secs),
    ));

    let upstream_manager = Arc::new(UpstreamManager::new(config.upstreams.clone()));
    let buffer_pool = Arc::new(BufferPool::with_config(16 * 1024, 4096));

    // IP Tracker initialization
    let ip_tracker = Arc::new(UserIpTracker::new());
    ip_tracker.load_limits(&config.access.user_max_unique_ips).await;

    // Middle proxy pool (optional)
    let me_pool: Option<Arc<MePool>> = None;

    let detected_ip = detect_ip().await;

    let mut listeners = Vec::new();

    for listener_conf in &config.server.listeners {
        let addr = SocketAddr::new(listener_conf.ip, config.server.port);
        let options = ListenOptions {
            ipv6_only: listener_conf.ip.is_ipv6(),
            ..Default::default()
        };

        match create_listener(addr, &options) {
            Ok(socket) => {
                let listener = TcpListener::from_std(socket.into())?;
                info!("Listening on {}", addr);
                listeners.push(listener);
            }
            Err(e) => {
                error!("Failed to bind to {}: {}", addr, e);
            }
        }
    }

    #[cfg(unix)]
    if let Some(ref unix_path) = config.server.listen_unix_sock {

        let std_listener = create_unix_listener(unix_path)?;
        let unix_listener = UnixListener::from_std(std_listener)?;

        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let ip_tracker = ip_tracker.clone();

        tokio::spawn(async move {

            let unix_conn_counter =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));

            loop {

                match unix_listener.accept().await {

                    Ok((stream, _)) => {

                        let conn_id = unix_conn_counter.fetch_add(
                            1,
                            std::sync::atomic::Ordering::Relaxed
                        );

                        let fake_peer =
                            SocketAddr::from(([127,0,0,1], conn_id as u16));

                        let config = config.clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let ip_tracker = ip_tracker.clone();

                        tokio::spawn(async move {

                            if let Err(e) = handle_client_stream(

                                stream,
                                fake_peer,
                                config,
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng,
                                me_pool,
                                ip_tracker.clone(),

                            ).await {

                                debug!(
                                    error = %e,
                                    "Unix socket connection error"
                                );
                            }

                        });

                    }

                    Err(e) => {

                        error!("Unix socket accept error: {}", e);

                        tokio::time::sleep(
                            Duration::from_millis(100)
                        ).await;

                    }

                }

            }

        });

    }

    for listener in listeners {

        let config = config.clone();
        let stats = stats.clone();
        let upstream_manager = upstream_manager.clone();
        let replay_checker = replay_checker.clone();
        let buffer_pool = buffer_pool.clone();
        let rng = rng.clone();
        let me_pool = me_pool.clone();
        let ip_tracker = ip_tracker.clone();

        tokio::spawn(async move {

            loop {

                match listener.accept().await {

                    Ok((stream, peer_addr)) => {

                        let config = config.clone();
                        let stats = stats.clone();
                        let upstream_manager = upstream_manager.clone();
                        let replay_checker = replay_checker.clone();
                        let buffer_pool = buffer_pool.clone();
                        let rng = rng.clone();
                        let me_pool = me_pool.clone();
                        let ip_tracker = ip_tracker.clone();

                        tokio::spawn(async move {

                            if let Err(e) = ClientHandler::new(

                                stream,
                                peer_addr,
                                config,
                                stats,
                                upstream_manager,
                                replay_checker,
                                buffer_pool,
                                rng,
                                me_pool,
                                ip_tracker,

                            )
                            .run()
                            .await
                            {

                                debug!(
                                    peer = %peer_addr,
                                    error = %e,
                                    "Connection error"
                                );

                            }

                        });

                    }

                    Err(e) => {

                        error!("Accept error: {}", e);

                        tokio::time::sleep(
                            Duration::from_millis(100)
                        ).await;

                    }

                }

            }

        });

    }

    signal::ctrl_c().await?;

    info!("Shutdown complete");

    Ok(())

}
