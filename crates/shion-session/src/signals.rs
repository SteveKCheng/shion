//! Signal names as SSH spells them (RFC 4254 §6.10: no `SIG` prefix).

use rustix::process::{Pid, Signal};
use tracing::debug;

/// The signals RFC 4254 names. Others can't be sent or reported by name.
const SIGNALS: &[(&str, Signal)] = &[
    ("ABRT", Signal::ABORT),
    ("ALRM", Signal::ALARM),
    ("FPE", Signal::FPE),
    ("HUP", Signal::HUP),
    ("ILL", Signal::ILL),
    ("INT", Signal::INT),
    ("KILL", Signal::KILL),
    ("PIPE", Signal::PIPE),
    ("QUIT", Signal::QUIT),
    ("SEGV", Signal::SEGV),
    ("TERM", Signal::TERM),
    ("USR1", Signal::USR1),
    ("USR2", Signal::USR2),
];

/// Maps the SSH name of a POSIX signal to a `Signal` value.
pub fn from_name(name: &str) -> Option<Signal> {
    SIGNALS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|&(_, sig)| sig)
}

/// SSH name of a raw signal number, as found in a wait status.
pub fn name(raw: i32) -> Option<&'static str> {
    SIGNALS
        .iter()
        .find(|(_, sig)| sig.as_raw() == raw)
        .map(|&(n, _)| n)
}

/// Sends `sig` to a process group. Returns whether it was delivered.
pub fn kill_group(pgid: Option<Pid>, sig: Signal) -> bool {
    let Some(pgid) = pgid else { return false };
    match rustix::process::kill_process_group(pgid, sig) {
        Ok(()) => true,
        Err(e) => {
            debug!(error = %e, pgid = pgid.as_raw_nonzero(), "kill failed");
            false
        }
    }
}

/// Restores the default action of the signals we may have been started
/// with ignored.
///
/// An ignored signal stays ignored across `exec`, so every child would
/// inherit that, and it happens easily: a non-interactive shell starts
/// background jobs (`shion-front &`) with SIGINT and SIGQUIT ignored, and
/// `nohup` ignores SIGHUP. Then `^C` wouldn't interrupt anything in a
/// session, and hanging up a conversation would do nothing. sshd resets
/// signals for its children too.
pub fn reset_ignored() {
    for signal in [
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ] {
        #[allow(unsafe_code)]
        // SAFETY: `signal` is unsafe because the handler it installs could
        // be any function, which then runs at awkward moments. `SIG_DFL`
        // installs no function at all, and dispositions are process-wide,
        // so it doesn't matter which thread does this.
        unsafe {
            libc::signal(signal, libc::SIG_DFL);
        }
    }
}
