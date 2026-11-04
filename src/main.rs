use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use ipssl::config::Config;
use ipssl::handler::Handler;
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

    let mut server = ipssl::serve(
        Handler::new(zone),
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
