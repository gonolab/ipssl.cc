//! Reload reports, so `systemctl reload` can wait for the server's result.
//!
//! The server keeps a small status file, `reload`, in its runtime
//! directory (`RuntimeDirectory=ipssl-dns` in the unit, so
//! `/run/ipssl-dns`). It names the server's process, counts the reloads it
//! has started (the generation) and holds the outcome of the latest one:
//! the SOA serial now served, or why the running config was kept. The file
//! is replaced in one step, so a reader never sees half of it.
//!
//! `ipssl-dns --reload <pid>` (the unit's `ExecReload`) checks the config
//! the way `--check` does, notes the generation, sends SIGHUP and waits
//! for a later generation to finish. It runs as the same user as the
//! server, which `DynamicUser=yes` gives every process of a unit.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use tracing::{debug, info, warn};

/// The runtime directory when systemd does not name one.
pub const DEFAULT_DIR: &str = "/run/ipssl-dns";

/// The status file's name in the runtime directory.
const FILE: &str = "reload";

/// The runtime directory: `$RUNTIME_DIRECTORY`, which systemd sets from
/// `RuntimeDirectory=` for every process of the unit, else [`DEFAULT_DIR`].
pub fn runtime_dir() -> PathBuf {
    let dirs = std::env::var("RUNTIME_DIRECTORY").unwrap_or_default();
    // Several directories are separated by colons; ours comes first.
    match dirs.split(':').next() {
        Some(first) if !first.is_empty() => PathBuf::from(first),
        _ => PathBuf::from(DEFAULT_DIR),
    }
}

/// What the status file says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// The server process that wrote it.
    pub pid: u32,
    /// Reloads started since the process started; 0 before the first.
    pub generation: u64,
    pub state: State,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Reload `generation` is running.
    Reloading,
    /// The zone with this SOA serial is served: since the start for
    /// generation 0, otherwise since reload `generation` succeeded.
    Serving(u32),
    /// Reload `generation` failed for this reason; the running config is
    /// still served.
    Failed(String),
}

impl Status {
    /// The file's contents, such as:
    ///
    /// ```text
    /// pid 1234
    /// generation 2
    /// ok 2026110502
    /// ```
    ///
    /// The last line is `reloading`, `ok <serial>` or `error <reason>`; the
    /// reason may run over several lines.
    pub fn render(&self) -> String {
        let state = match &self.state {
            State::Reloading => "reloading".to_string(),
            State::Serving(serial) => format!("ok {serial}"),
            State::Failed(reason) => format!("error {reason}"),
        };
        format!(
            "pid {}\ngeneration {}\n{state}\n",
            self.pid, self.generation
        )
    }

    /// Reads what [`Self::render`] wrote; `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        let mut lines = text.splitn(3, '\n');
        let pid = lines.next()?.strip_prefix("pid ")?.parse().ok()?;
        let generation = lines.next()?.strip_prefix("generation ")?.parse().ok()?;
        let state = lines.next()?.strip_suffix('\n')?;
        let state = if state == "reloading" {
            State::Reloading
        } else if let Some(serial) = state.strip_prefix("ok ") {
            State::Serving(serial.parse().ok()?)
        } else {
            State::Failed(state.strip_prefix("error ")?.to_string())
        };
        Some(Self {
            pid,
            generation,
            state,
        })
    }

    /// Reads the status file in `dir`; `None` if there is none yet.
    pub fn read(dir: &Path) -> io::Result<Option<Self>> {
        let path = dir.join(FILE);
        match fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).map(Some).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not a reload status", path.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Replaces the status file in `dir`: written next to it, then renamed
    /// over it, so a reader sees the old file or the new one.
    pub fn write(&self, dir: &Path) -> io::Result<()> {
        let tmp = dir.join(format!("{FILE}.tmp"));
        fs::write(&tmp, self.render())?;
        fs::rename(&tmp, dir.join(FILE))
    }
}

/// Keeps the server's status file up to date. Every report tries to write
/// it, so a write that failed once (a full `/run`, the directory removed
/// and made again) does not stop later reports. Without a runtime
/// directory (when run by hand, say) the server works as before; only
/// `--reload` cannot be used then.
pub struct Reporter {
    pid: u32,
    dir: PathBuf,
    /// Whether `dir` existed at the start. If not, failed writes are
    /// expected and only logged at debug level.
    expected: bool,
    state: Mutex<Progress>,
}

struct Progress {
    /// The generation written last.
    generation: u64,
    /// Whether the last write failed, so a failure is logged once until
    /// a write works again.
    failing: bool,
}

impl Reporter {
    /// Reports to the status file in `dir`.
    pub fn new(dir: PathBuf) -> Self {
        let expected = dir.is_dir();
        if !expected {
            debug!(dir = %dir.display(), "no runtime directory, so reloads are not reported");
        }
        Self {
            pid: std::process::id(),
            dir,
            expected,
            state: Mutex::new(Progress {
                generation: 0,
                failing: false,
            }),
        }
    }

    /// The server serves `serial` after starting.
    pub fn started(&self, serial: u32) {
        self.report(|_| (0, State::Serving(serial)));
    }

    /// A reload has started.
    pub fn reloading(&self) {
        self.report(|generation| (generation + 1, State::Reloading));
    }

    /// The reload that started last is done: it serves `serial`, or it
    /// failed for `reason`.
    pub fn finished(&self, result: Result<u32, String>) {
        let state = match result {
            Ok(serial) => State::Serving(serial),
            Err(reason) => State::Failed(reason),
        };
        self.report(|generation| (generation, state));
    }

    fn report(&self, next: impl FnOnce(u64) -> (u64, State)) {
        let mut progress = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let (generation, state) = next(progress.generation);
        progress.generation = generation;
        let status = Status {
            pid: self.pid,
            generation,
            state,
        };
        let dir = self.dir.display();
        match status.write(&self.dir) {
            Ok(()) => {
                if progress.failing && self.expected {
                    info!(%dir, "writing the reload status again");
                }
                progress.failing = false;
            }
            Err(error) if self.expected && !progress.failing => {
                warn!(%dir, %error, "cannot write the reload status, so `ipssl-dns --reload` cannot confirm reloads until a later write works");
                progress.failing = true;
            }
            Err(error) => {
                debug!(%dir, %error, "cannot write the reload status");
                progress.failing = true;
            }
        }
    }
}

/// Sends SIGHUP to `pid`, which makes the server reload.
#[cfg(unix)]
pub fn send_hangup(pid: u32) -> io::Result<()> {
    // 0 and negative numbers would signal whole process groups.
    let pid = libc::pid_t::try_from(pid)
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid process id"))?;
    // SAFETY: kill(2) takes plain integers and touches no memory of ours.
    if unsafe { libc::kill(pid, libc::SIGHUP) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        for state in [
            State::Reloading,
            State::Serving(2026110502),
            State::Failed("reading config.toml: no such file".into()),
            // TOML errors span several lines.
            State::Failed("parsing config.toml\n  |\n1 | x\n  | ^\n".into()),
            State::Failed(String::new()),
        ] {
            let status = Status {
                pid: 1234,
                generation: 7,
                state,
            };
            assert_eq!(Status::parse(&status.render()), Some(status.clone()));
        }
        assert_eq!(
            Status {
                pid: 1,
                generation: 0,
                state: State::Serving(5),
            }
            .render(),
            "pid 1\ngeneration 0\nok 5\n"
        );
    }

    #[test]
    fn other_text_is_no_status() {
        for text in [
            "",
            "pid 1\n",
            "pid 1\ngeneration 2\n",
            "pid 1\ngeneration 2\nok\n",
            "pid 1\ngeneration 2\nok 5",
            "pid x\ngeneration 2\nok 5\n",
            "pid 1\ngeneration -2\nok 5\n",
            "pid 1\ngeneration 2\ndone\n",
        ] {
            assert_eq!(Status::parse(text), None, "{text:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_signal_process_groups() {
        assert!(send_hangup(0).is_err());
        assert!(send_hangup(u32::MAX).is_err());
    }
}
