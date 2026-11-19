use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail, ensure};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use ipssl::Listener;
use ipssl::acme::{Api, Challenges, Node};
use ipssl::config::Config;
use ipssl::handler::Handler;
use ipssl::ratelimit::RateLimiter;
use ipssl::reload::{Reporter, runtime_dir};
use ipssl::zone::Zone;

/// How long `--reload` waits for the server's result. Well below the 90
/// seconds systemd gives `ExecReload` by default, so a server that never
/// answers fails the reload with this program's error, not systemd's.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

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

    /// Check the config like --check, make the DNS server with this process
    /// id reload it, and wait for the result: exit 0 once it serves the new
    /// zone, 1 if it kept the running config. For `ExecReload` in the
    /// systemd unit, which passes $MAINPID.
    #[arg(
        long,
        value_name = "PID",
        conflicts_with_all = ["check", "acme_api"],
        value_parser = clap::value_parser!(u32).range(1..=i64::from(i32::MAX)),
    )]
    reload: Option<u32>,
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
        // The API built the same zone, so this cannot fail.
        if let Ok(zone) = Zone::from_config(&config) {
            warn_about_challenges(&zone);
        }
        if args.check {
            info!(nodes = ?api.nodes(), "config OK");
            return Ok(());
        }
        return run_acme_api(&config, api).await;
    }
    if args.check {
        let (config, zone) = load(&args.config)?;
        warn_about(&config, &zone);
        info!("config OK");
        return Ok(());
    }
    if let Some(pid) = args.reload {
        return reload_server(&args.config, pid).await;
    }

    // SIGHUP kills a process that does not handle it. Take it over before
    // anything slow, so `systemctl reload` right after the start is never
    // fatal: a SIGHUP that arrives while the config loads or the sockets
    // bind is queued and reloads once the server runs.
    #[cfg(unix)]
    let hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("installing the SIGHUP handler")?;

    let (config, zone) = load(&args.config)?;
    warn_about(&config, &zone);
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
        let node = Node::from_config(handler.clone(), store, acme)?;
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
        Arc::new(Reporter::new(runtime_dir())),
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
    let config = load_config(path)?;
    let zone = Zone::from_config(&config)?;
    Ok((config, zone))
}

/// Loads and checks the config at `path`, without its zone.
fn load_config(path: &Path) -> Result<Config> {
    let config = Config::load(path)?;
    config
        .validate()
        .with_context(|| format!("checking {}", path.display()))?;
    Ok(config)
}

/// Logs settings that are allowed but probably not what was meant.
fn warn_about(config: &Config, zone: &Zone) {
    if let Some(acme) = &config.acme {
        if acme.writers.is_empty() {
            warn!("acme.writers is empty, so no challenge can be published");
        }
        warn_about_challenges(zone);
    }
}

/// Lists the names refused DNS-01 challenges only because of a fixed host
/// right below them, see [`Zone::check_challenge`].
fn warn_about_challenges(zone: &Zone) {
    let names = zone.public_host_parents();
    if !names.is_empty() {
        warn!(
            names = names.join(", "),
            "these names take no DNS-01 challenges: a wildcard certificate for them would also cover a fixed host with a public address"
        );
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

/// Serves the DNS-01 challenge API, and its metrics with a `[metrics]`
/// section, until SIGTERM or Ctrl-C. Config changes need a restart.
async fn run_acme_api(config: &Config, api: Api) -> Result<()> {
    let acme = config.acme.as_ref().expect("checked by Api::from_config");
    let addr = acme.api_listen;
    let listener = ipssl::bind_tcp(addr).with_context(|| format!("binding acme api {addr}"))?;
    info!(%addr, nodes = ?api.nodes(), "serving the DNS-01 challenge API");
    let api = Arc::new(api);
    let mut tasks = vec![tokio::spawn(api.clone().serve(listener))];

    if let Some(metrics) = &config.metrics {
        let addr = metrics.listen;
        // Not fatal, unlike in the DNS server: a host running both from one
        // config has the DNS server on this address already, and the API
        // works without metrics.
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "serving API metrics at /metrics");
                tasks.push(tokio::spawn(ipssl::http::serve_metrics(
                    listener,
                    move || api.render_metrics(),
                )));
            }
            Err(error) => warn!(%addr, %error, "cannot serve API metrics; running without them"),
        }
    }

    shutdown_signal().await;
    info!("shutting down");
    for task in tasks {
        task.abort();
    }
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

/// `--reload <pid>`: checks the config at `path` the way `--check` does,
/// sends SIGHUP to the server `pid` and waits until it reports the reload
/// in its runtime directory (see [`ipssl::reload`]). Fails if the check
/// fails, if the server keeps its running config, or if it reports nothing
/// within [`RELOAD_TIMEOUT`].
#[cfg(unix)]
async fn reload_server(path: &Path, pid: u32) -> Result<()> {
    use ipssl::reload::{State, Status, send_hangup};

    // A config the check refuses is not sent: the server would refuse it too.
    load(path)?;
    let dir = runtime_dir();
    ensure!(
        dir.is_dir(),
        "{} does not exist, so the reload cannot be confirmed; the service needs RuntimeDirectory=ipssl-dns",
        dir.display()
    );
    let read = || -> Result<Option<Status>> {
        let status = Status::read(&dir).with_context(|| format!("reading {}", dir.display()))?;
        // A file left by an earlier process says nothing about this one.
        Ok(status.filter(|s| s.pid == pid))
    };

    // Wait for a reload that starts after the SIGHUP. One already running
    // may have read the file before it was checked here; the server
    // finishes that one, then starts another for this signal. Either way,
    // the reload to wait for has a generation past the current one.
    let before = read()?;
    let mut reported = before.is_some();
    let target = before.map_or(0, |s| s.generation) + 1;
    send_hangup(pid).with_context(|| format!("sending SIGHUP to process {pid}"))?;

    let deadline = tokio::time::Instant::now() + RELOAD_TIMEOUT;
    loop {
        if let Some(status) = read()? {
            reported = true;
            if status.generation >= target {
                match status.state {
                    State::Serving(serial) => {
                        info!(serial, "the server reloaded the config");
                        return Ok(());
                    }
                    State::Failed(reason) => {
                        bail!("reload failed, the server keeps its running config: {reason}")
                    }
                    State::Reloading => {}
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            let secs = RELOAD_TIMEOUT.as_secs();
            if reported {
                bail!("process {pid} did not finish the reload within {secs} seconds; see its log");
            }
            bail!(
                "process {pid} reported no reload in {} within {secs} seconds; if it runs an ipssl-dns without reload reports, restart it instead",
                dir.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(not(unix))]
async fn reload_server(_path: &Path, _pid: u32) -> Result<()> {
    bail!("--reload needs a Unix system")
}

/// Reloads the config on every SIGHUP (`systemctl reload ipssl-dns`).
/// A config that fails to load or validate is logged and the running one
/// kept. `hangup` is installed at the very start of `main`. Every reload
/// and its outcome go to `reporter` for `--reload`.
#[cfg(unix)]
async fn reload_on_sighup(
    mut hangup: tokio::signal::unix::Signal,
    path: PathBuf,
    running: Config,
    handler: Handler,
    reporter: Arc<Reporter>,
) {
    reporter.started(running.soa.serial);
    let running = Arc::new(running);
    while hangup.recv().await.is_some() {
        // Reading the file, parsing it and building the zone block, so keep
        // them off the async workers that answer queries.
        let task = {
            let (path, running, handler, reporter) = (
                path.clone(),
                running.clone(),
                handler.clone(),
                reporter.clone(),
            );
            tokio::task::spawn_blocking(move || {
                reporter.reloading();
                let result = reload(&path, &running, &handler);
                reporter.finished(result.as_ref().copied().map_err(|e| format!("{e:#}")));
                result
            })
        };
        let result = match task.await {
            Ok(result) => result,
            Err(e) => {
                // The task ended before it could report.
                let e = anyhow!("reload task failed: {e}");
                reporter.finished(Err(e.to_string()));
                Err(e)
            }
        };
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
///
/// The zone is checked against what keeps running too: a process that
/// started with `[acme]` answers challenge names from its challenge store
/// until it exits, so a reload that drops `[acme]` and configures records
/// for such a name fails instead of leaving them hidden.
#[cfg(unix)]
fn reload(path: &Path, running: &Config, handler: &Handler) -> Result<u32> {
    let config = load_config(path)?;
    for setting in config.restart_only_changes(running) {
        warn!(setting, "changed, but only takes effect after a restart");
    }
    let zone = Zone::for_running(&config, running.acme.is_some())?;
    // Challenges are taken as long as the process runs with [acme].
    if running.acme.is_some() {
        warn_about_challenges(&zone);
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
