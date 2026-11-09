use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ipssl::acme::{Api, Challenges, Node};
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

    /// Run the DNS-01 challenge API (`[acme]` in the config) instead of the
    /// DNS server.
    #[arg(long)]
    acme_api: bool,
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
        // No color codes in journald or log files.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    if args.acme_api {
        let api = Api::from_config(&config)?;
        if args.check {
            info!(nodes = ?api.nodes(), "config OK");
            return Ok(());
        }
        return run_acme_api(&config, api).await;
    }

    let zone = Zone::from_config(&config)?;
    let limiter = RateLimiter::from_config(&config.rate_limit)?;
    if let Some(acme) = &config.acme
        && acme.writers.is_empty()
    {
        warn!("acme.writers is empty, so no challenge can be published");
    }
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
    let mut handler = Handler::new(zone).with_rate_limiter(limiter);

    if let Some(acme) = &config.acme {
        let addr = acme.listen;
        let listener = ipssl::bind_tcp(addr).with_context(|| format!("binding acme {addr}"))?;
        info!(%addr, writers = ?acme.writers, "accepting DNS-01 challenges");
        let store = Arc::new(Challenges::new());
        handler = handler.with_challenges(store.clone());
        tokio::spawn(purge_challenges(store.clone()));
        let node = Arc::new(Node::new(handler.clone(), store, &acme.writers));
        tokio::spawn(ipssl::http::serve(listener, move |req| {
            let node = node.clone();
            async move { node.handle(req).await }
        }));
    }

    if let Some(metrics) = &config.metrics {
        let addr = metrics.listen;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding metrics {addr}"))?;
        info!(%addr, "serving metrics at /metrics");
        let handler = handler.clone();
        tokio::spawn(ipssl::http::serve_metrics(listener, move || {
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

/// Serves the DNS-01 challenge API until SIGTERM or Ctrl-C. Config changes
/// need a restart.
async fn run_acme_api(config: &Config, api: Api) -> Result<()> {
    let acme = config.acme.as_ref().expect("checked by Api::from_config");
    let addr = acme.api_listen;
    let listener = ipssl::bind_tcp(addr).with_context(|| format!("binding acme api {addr}"))?;
    info!(%addr, nodes = ?api.nodes(), "serving the DNS-01 challenge API");
    let api = Arc::new(api);
    let server = tokio::spawn(ipssl::http::serve(listener, move |req| {
        let api = api.clone();
        async move { api.handle(req).await }
    }));
    shutdown_signal().await;
    info!("shutting down");
    server.abort();
    Ok(())
}

/// Forgets expired challenge values once a minute, so the store does not
/// fill up with values nobody asked for again.
async fn purge_challenges(store: Arc<Challenges>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        store.purge();
    }
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
