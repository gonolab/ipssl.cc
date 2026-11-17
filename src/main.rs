use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ipssl::Listener;
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
    if args.acme_api {
        let config = Config::load(&args.config)?;
        let api = Api::from_config(&config)?;
        if args.check {
            info!(nodes = ?api.nodes(), "config OK");
            return Ok(());
        }
        return run_acme_api(&config, api).await;
    }
    if args.check {
        let (config, _) = load(&args.config)?;
        warn_about(&config);
        info!("config OK");
        return Ok(());
    }

    // SIGHUP kills a process that does not handle it. Take it over before
    // anything slow, so `systemctl reload` right after the start is never
    // fatal: a SIGHUP that arrives while the config loads or the sockets
    // bind is queued and reloads once the server runs.
    #[cfg(unix)]
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing the SIGHUP handler")?;

    let (config, zone) = load(&args.config)?;
    warn_about(&config);
    let limiter = RateLimiter::from_config(&config.rate_limit)?;
    let listeners = bind_dns(&config.listen)?;

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
        let node = Node::new(handler.clone(), store, &acme.writers);
        tokio::spawn(node.serve(listener));
    }

    if let Some(metrics) = &config.metrics {
        let addr = metrics.listen;
        // IPv6-only for IPv6 addresses, like every other listener, so the
        // overlap check in `Config::validate` holds.
        let listener = ipssl::bind_tcp(addr).with_context(|| format!("binding metrics {addr}"))?;
        info!(%addr, "serving metrics at /metrics");
        let handler = handler.clone();
        tokio::spawn(ipssl::http::serve_metrics(listener, move || {
            handler.render_metrics()
        }));
    }
    #[cfg(unix)]
    tokio::spawn(reload_on_sighup(
        hangup,
        args.config,
        config.clone(),
        handler.clone(),
    ));

    // A listener that stops on its own ends this with an error, and the
    // non-zero exit lets systemd restart the service with all of them.
    ipssl::serve_until(
        handler,
        listeners,
        Duration::from_secs(config.tcp_timeout_secs),
        async {
            shutdown_signal().await;
            info!("shutting down");
        },
    )
    .await
}

/// Loads the config at `path`, checks it and builds its zone: the same
/// steps for `--check`, startup and reload, so a config one accepts the
/// others accept too.
fn load(path: &Path) -> Result<(Config, Zone)> {
    let config = Config::load(path)?;
    config
        .validate()
        .with_context(|| format!("checking {}", path.display()))?;
    let zone = Zone::from_config(&config)?;
    Ok((config, zone))
}

/// Logs settings that are allowed but probably not what was meant.
fn warn_about(config: &Config) {
    if let Some(acme) = &config.acme
        && acme.writers.is_empty()
    {
        warn!("acme.writers is empty, so no challenge can be published");
    }
}

/// Binds UDP and TCP on every DNS address. On a kernel without IPv6,
/// `[::]` (in the default `listen`) is skipped with a warning; every other
/// failure is fatal.
fn bind_dns(addrs: &[SocketAddr]) -> Result<Vec<Listener>> {
    let mut listeners = Vec::new();
    for &addr in addrs {
        let udp = match ipssl::bind_udp(addr) {
            Ok(socket) => socket,
            Err(e) if ipssl::ipv6_unavailable(addr, &e) => {
                warn!(%addr, "not listening: this system has no IPv6 ({e})");
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("binding udp {addr}")),
        };
        let tcp = ipssl::bind_tcp(addr).with_context(|| format!("binding tcp {addr}"))?;
        info!(%addr, "listening (udp + tcp)");
        listeners.push(Listener::Udp(udp));
        listeners.push(Listener::Tcp(tcp));
    }
    ensure!(
        !listeners.is_empty(),
        "no DNS listener: every address in listen was skipped"
    );
    Ok(listeners)
}

/// Serves the DNS-01 challenge API until SIGTERM or Ctrl-C. Config changes
/// need a restart.
async fn run_acme_api(config: &Config, api: Api) -> Result<()> {
    let acme = config.acme.as_ref().expect("checked by Api::from_config");
    let addr = acme.api_listen;
    let listener = ipssl::bind_tcp(addr).with_context(|| format!("binding acme api {addr}"))?;
    info!(%addr, nodes = ?api.nodes(), "serving the DNS-01 challenge API");
    let api = Arc::new(api);
    let server = tokio::spawn(api.serve(listener));
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
/// A config that fails to load or validate is logged and the running one
/// kept. `hangup` is installed at the very start of `main`.
#[cfg(unix)]
async fn reload_on_sighup(
    mut hangup: tokio::signal::unix::Signal,
    path: PathBuf,
    running: Config,
    handler: Handler,
) {
    let running = Arc::new(running);
    while hangup.recv().await.is_some() {
        // Reading the file, parsing it and building the zone block, so keep
        // them off the async workers that answer queries.
        let task = {
            let (path, running, handler) = (path.clone(), running.clone(), handler.clone());
            tokio::task::spawn_blocking(move || reload(&path, &running, &handler))
        };
        let result = task
            .await
            .unwrap_or_else(|e| Err(anyhow!("reload task failed: {e}")));
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
/// until the process is restarted. They are still validated, so a reload
/// never accepts a config a restart would refuse.
#[cfg(unix)]
fn reload(path: &Path, running: &Config, handler: &Handler) -> Result<u32> {
    let (config, zone) = load(path)?;
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
