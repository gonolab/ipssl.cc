use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ipssl::config::Config;
use ipssl::handler::Handler;
use ipssl::ratelimit::RateLimiter;
use ipssl::zone::Zone;

/// Authoritative DNS server that answers 10-0-0-1.<domain> with 10.0.0.1.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the config file.
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Validate the config and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // hickory-server logs every request (with client IPs) at info level;
    // keep it quiet by default. Override with RUST_LOG.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,hickory_server=warn")),
        )
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let zone = Zone::from_config(&config)?;
    let limiter = RateLimiter::from_config(&config.rate_limit)?;
    if args.check {
        info!("config OK");
        return Ok(());
    }

    let mut udp = Vec::new();
    let mut tcp = Vec::new();
    for addr in &config.listen {
        udp.push(ipssl::bind_udp(*addr).with_context(|| format!("binding udp {addr}"))?);
        tcp.push(ipssl::bind_tcp(*addr).with_context(|| format!("binding tcp {addr}"))?);
        info!(%addr, "listening (udp + tcp)");
    }

    if limiter.is_none() {
        warn!("UDP rate limiting is off");
    }
    let handler = Handler::new(zone).with_rate_limiter(limiter);

    if let Some(metrics) = &config.metrics {
        let addr = metrics.listen;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding metrics {addr}"))?;
        info!(%addr, "serving metrics at /metrics");
        let handler = handler.clone();
        tokio::spawn(ipssl::http::serve(listener, move || {
            handler.render_metrics()
        }));
    }
    #[cfg(unix)]
    tokio::spawn(reload_on_sighup(
        args.config,
        config.clone(),
        handler.clone(),
    ));

    let mut server = ipssl::serve(
        handler,
        udp,
        tcp,
        Duration::from_secs(config.tcp_timeout_secs),
    );

    let token = server.shutdown_token().clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        info!("shutting down");
        token.cancel();
    });

    server.block_until_done().await?;
    Ok(())
}

/// Reloads the config on every SIGHUP (`systemctl reload ipssl-dns`).
/// A config that fails to load is logged and the running zone kept.
#[cfg(unix)]
async fn reload_on_sighup(path: PathBuf, running: Config, handler: Handler) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup()).expect("installing SIGHUP handler");
    while hangup.recv().await.is_some() {
        let result = reload(&path, &running, &handler);
        handler.metrics().reload(result.is_ok());
        match result {
            Ok(serial) => info!(serial, "config reloaded"),
            Err(e) => error!("reload failed, keeping the running config: {e:#}"),
        }
    }
}

/// Loads the config at `path` into `handler` and returns the new SOA serial.
/// `running` is the config the process started with: settings that need a
/// restart are compared against it, so the warning repeats on every reload
/// until the process is restarted.
#[cfg(unix)]
fn reload(path: &std::path::Path, running: &Config, handler: &Handler) -> Result<u32> {
    let config = Config::load(path)?;
    let zone = Zone::from_config(&config)?;
    for setting in config.restart_only_changes(running) {
        warn!(setting, "changed, but only takes effect after a restart");
    }
    handler.set_zone(zone);
    Ok(config.soa.serial)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
