//! Pseudo-terminals for `pty-req` (design §5.4). Linux-only for now.
//!
//! A pty is a pair of character devices. The child gets the *slave*
//! (`/dev/pts/N`) as its stdin, stdout, stderr and controlling terminal;
//! we keep the *master*. What we write to the master is what the child
//! reads as keyboard input, after the line discipline has processed it
//! (echo, `^C` → `SIGINT`, line editing). What the child writes comes out
//! of the master, with the slave's output processing applied (`\n` →
//! `\r\n`). Terminal modes from the client configure that processing.

use std::ffi::OsString;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use rustix::process::Pid;
use rustix::pty::OpenptFlags;
use rustix::termios::{
    ControlModes, InputModes, LocalModes, OptionalActions, OutputModes, SpecialCodeIndex, Termios,
    Winsize,
};
use shion_fd::FdStream;
use shion_wire::message::{PtyRequest, WindowSize};
use shion_wire::modes::{self, DISABLED_CHAR, opcode};
use tokio::process::Command;
use tracing::debug;

/// The state of an open pseudo-terminal.
#[derive(Debug)]
pub struct Terminal {
    /// Master side of the pseudo-terminal.
    /// 
    /// Used for `ioctl`s (window size, foreground process group). The I/O
    /// pumps get their own duplicate from [`Terminal::stream`].
    master: OwnedFd,

    /// Slave side of the pseudo-terminal.
    ///
    /// Held until [`Terminal::close_slave`]. Once the child has its copies,
    /// ours must be closed: the master only reports end-of-file (as `EIO`)
    /// when *every* copy of the slave is closed.
    slave: Option<OwnedFd>,

    /// The slave's path, for setting the `SSH_TTY` environment variable.
    ///
    /// The session process does not use this path for anything itself.
    path: PathBuf,

    /// The client's `TERM` environment variable to propagate.
    term: String,
}

impl Terminal {
    /// Opens a pty pair, configured with the window size and modes from
    /// `request`.
    ///
    /// # Errors
    /// If no pty can be allocated or configured.
    pub fn open(request: &PtyRequest) -> io::Result<Self> {
        // NOCTTY: opening a terminal must not make it *our* controlling
        // terminal. CLOEXEC: children only get the copies we give them.
        let flags = OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC;
        let master = rustix::pty::openpt(flags)?;

        // Traditional POSIX stipulates calling grantpt to change ownership/permissions on 
        // the slave pseudo-terminal device.  This is wholly unnecessary in sandboxes, where
        // the slave device will have the correct ownership/permissions to begin with,
        // and usually be reduced to a no-op.
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;

        let path = PathBuf::from(OsString::from_vec(
            rustix::pty::ptsname(&master, Vec::new())?.into_bytes(),
        ));

        // Opens the slave through the master instead of by path, so nothing
        // racing on /dev/pts can substitute another device (Linux ≥ 4.13).
        let slave = rustix::pty::ioctl_tiocgptpeer(&master, flags)?;

        // Initial terminal settings
        rustix::termios::tcsetwinsize(&slave, winsize(request.size))?;
        let mut termios = rustix::termios::tcgetattr(&slave)?;
        apply_modes(&mut termios, &request.modes);
        rustix::termios::tcsetattr(&slave, OptionalActions::Now, &termios)?;

        Ok(Self {
            master,
            slave: Some(slave),
            path,
            term: request.term.clone(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn term(&self) -> &str {
        &self.term
    }

    /// Makes `cmd` run in a new session with the slave as its stdin,
    /// stdout, stderr and controlling terminal.
    ///
    /// # Errors
    /// If the slave was already closed, or can't be duplicated.
    pub fn configure(&self, cmd: &mut Command) -> io::Result<()> {
        let slave = self
            .slave
            .as_ref()
            .ok_or_else(|| io::Error::other("the terminal already has a session"))?;
        cmd.stdin(slave.try_clone()?)
            .stdout(slave.try_clone()?)
            .stderr(slave.try_clone()?);

        // This closure owns one more copy of the slave, so it can name the
        // terminal without touching raw fd numbers. `cmd` drops it after
        // spawning, and in the child it's `O_CLOEXEC`.
        let ctty = slave.try_clone()?;
        let become_session_leader = move || -> io::Result<()> {
            // A new session, with this process as leader of a new process
            // group (whose ID is the child's PID), and no controlling
            // terminal yet...
            rustix::process::setsid()?;
            // ...until we give it ours. Linux would do this implicitly when
            // a session leader opens a tty without `O_NOCTTY`, but the
            // explicit ioctl doesn't depend on that.
            rustix::process::ioctl_tiocsctty(&ctty)?;
            Ok(())
        };

        // `pre_exec` runs the closure in the child between `fork` and
        // `exec`. That's `unsafe` because only async-signal-safe operations
        // are allowed there. In particular no memory allocation, since another
        // thread may have held the allocator's lock at the moment of
        // `fork`, and the lock was copied in that state.
        #[allow(unsafe_code)]
        // SAFETY: `setsid` and `ioctl` are async-signal-safe, and rustix
        // issues them as plain system calls. The `?` conversions make an
        // `io::Error` from an errno, which doesn't allocate.
        unsafe {
            cmd.pre_exec(become_session_leader);
        }

        Ok(())
    }

    /// Closes our copy of the slave. Call once the child has started.
    pub fn close_slave(&mut self) {
        self.slave = None; // dropping the `OwnedFd` closes it
    }

    /// A non-blocking handle on the master, for reading the child's output
    /// and writing its input.
    ///
    /// # Errors
    /// If the master can't be duplicated or registered with tokio.
    pub fn stream(&self) -> io::Result<FdStream> {
        FdStream::new(self.master.try_clone()?)?
            .map_err(|_| io::Error::other("cannot poll the pty master"))
    }

    /// Changes the window size. The kernel sends `SIGWINCH` to the
    /// terminal's foreground process group.
    ///
    /// # Errors
    /// If the `ioctl` fails.
    pub fn resize(&self, size: WindowSize) -> io::Result<()> {
        Ok(rustix::termios::tcsetwinsize(&self.master, winsize(size))?)
    }

    /// The process group in the foreground, which is the one that typing
    /// `^C` would signal. A job-control shell moves each job it runs into
    /// its own group.
    pub fn foreground_group(&self) -> Option<Pid> {
        rustix::termios::tcgetpgrp(&self.master).ok()
    }
}

fn winsize(size: WindowSize) -> Winsize {
    let clamp = |n: u64| u16::try_from(n).unwrap_or(u16::MAX);
    Winsize {
        ws_row: clamp(size.rows),
        ws_col: clamp(size.cols),
        ws_xpixel: clamp(size.width_px),
        ws_ypixel: clamp(size.height_px),
    }
}

/// "Terminal modes" that can be requested by the client as part of opening
/// a pseudo-terminal.
enum Mode {
    Char(SpecialCodeIndex),
    Input(InputModes),
    Local(LocalModes),
    Output(OutputModes),
    Control(ControlModes),
    /// `CS7` and `CS8` are values of the multi-bit `CSIZE` field, not
    /// independent flags.
    CharSize(ControlModes),
    InputSpeed,
    OutputSpeed,
}

/// Maps an opcode (§8 of RFC 4254) to its `termios` setting. 
/// 
/// Opcodes for settings Linux doesn't have (`VDSUSP`, `VSTATUS`, `VFLUSH`) 
/// map to `None`, like unknown ones.
fn mode(op: u8) -> Option<Mode> {
    use Mode::{Char, CharSize, Control, Input, InputSpeed, Local, Output, OutputSpeed};
    // `opcode::…` are `const`s, so they can be used as patterns.
    Some(match op {
        opcode::VINTR => Char(SpecialCodeIndex::VINTR),
        opcode::VQUIT => Char(SpecialCodeIndex::VQUIT),
        opcode::VERASE => Char(SpecialCodeIndex::VERASE),
        opcode::VKILL => Char(SpecialCodeIndex::VKILL),
        opcode::VEOF => Char(SpecialCodeIndex::VEOF),
        opcode::VEOL => Char(SpecialCodeIndex::VEOL),
        opcode::VEOL2 => Char(SpecialCodeIndex::VEOL2),
        opcode::VSTART => Char(SpecialCodeIndex::VSTART),
        opcode::VSTOP => Char(SpecialCodeIndex::VSTOP),
        opcode::VSUSP => Char(SpecialCodeIndex::VSUSP),
        opcode::VREPRINT => Char(SpecialCodeIndex::VREPRINT),
        opcode::VWERASE => Char(SpecialCodeIndex::VWERASE),
        opcode::VLNEXT => Char(SpecialCodeIndex::VLNEXT),
        opcode::VSWTCH => Char(SpecialCodeIndex::VSWTC), // Linux's spelling
        opcode::VDISCARD => Char(SpecialCodeIndex::VDISCARD),

        opcode::IGNPAR => Input(InputModes::IGNPAR),
        opcode::PARMRK => Input(InputModes::PARMRK),
        opcode::INPCK => Input(InputModes::INPCK),
        opcode::ISTRIP => Input(InputModes::ISTRIP),
        opcode::INLCR => Input(InputModes::INLCR),
        opcode::IGNCR => Input(InputModes::IGNCR),
        opcode::ICRNL => Input(InputModes::ICRNL),
        opcode::IUCLC => Input(InputModes::IUCLC),
        opcode::IXON => Input(InputModes::IXON),
        opcode::IXANY => Input(InputModes::IXANY),
        opcode::IXOFF => Input(InputModes::IXOFF),
        opcode::IMAXBEL => Input(InputModes::IMAXBEL),
        opcode::IUTF8 => Input(InputModes::IUTF8),

        opcode::ISIG => Local(LocalModes::ISIG),
        opcode::ICANON => Local(LocalModes::ICANON),
        opcode::XCASE => Local(LocalModes::XCASE),
        opcode::ECHO => Local(LocalModes::ECHO),
        opcode::ECHOE => Local(LocalModes::ECHOE),
        opcode::ECHOK => Local(LocalModes::ECHOK),
        opcode::ECHONL => Local(LocalModes::ECHONL),
        opcode::NOFLSH => Local(LocalModes::NOFLSH),
        opcode::TOSTOP => Local(LocalModes::TOSTOP),
        opcode::IEXTEN => Local(LocalModes::IEXTEN),
        opcode::ECHOCTL => Local(LocalModes::ECHOCTL),
        opcode::ECHOKE => Local(LocalModes::ECHOKE),
        opcode::PENDIN => Local(LocalModes::PENDIN),

        opcode::OPOST => Output(OutputModes::OPOST),
        opcode::OLCUC => Output(OutputModes::OLCUC),
        opcode::ONLCR => Output(OutputModes::ONLCR),
        opcode::OCRNL => Output(OutputModes::OCRNL),
        opcode::ONOCR => Output(OutputModes::ONOCR),
        opcode::ONLRET => Output(OutputModes::ONLRET),

        opcode::CS7 => CharSize(ControlModes::CS7),
        opcode::CS8 => CharSize(ControlModes::CS8),
        opcode::PARENB => Control(ControlModes::PARENB),
        opcode::PARODD => Control(ControlModes::PARODD),

        opcode::TTY_OP_ISPEED => InputSpeed,
        opcode::TTY_OP_OSPEED => OutputSpeed,
        _ => return None,
    })
}

/// Applies an encoded terminal-modes blob (from the SSH message) to `termios`. 
/// 
/// Modes we can't apply are skipped, as OpenSSH does: a client's terminal settings 
/// are a preference, not a reason to refuse the pty.
fn apply_modes(termios: &mut Termios, blob: &[u8]) {
    for (op, arg) in modes::decode(blob) {
        let on = arg != 0;
        match mode(op) {
            Some(Mode::Char(index)) => {
                termios.special_codes[index] = match arg {
                    DISABLED_CHAR => 0, // Linux's _POSIX_VDISABLE
                    // A value that doesn't fit in a byte is nonsense; leave
                    // the default.
                    _ => match u8::try_from(arg) {
                        Ok(c) => c,
                        Err(_) => continue,
                    },
                };
            }
            // bitflags' `set(flag, bool)` sets or clears.
            Some(Mode::Input(flag)) => termios.input_modes.set(flag, on),
            Some(Mode::Local(flag)) => termios.local_modes.set(flag, on),
            Some(Mode::Output(flag)) => termios.output_modes.set(flag, on),
            Some(Mode::Control(flag)) => termios.control_modes.set(flag, on),
            Some(Mode::CharSize(size)) => {
                if on {
                    termios.control_modes.remove(ControlModes::CSIZE);
                    termios.control_modes.insert(size);
                }
            }
            // Meaningless for a pty, but harmless; `stty` shows them.
            Some(Mode::InputSpeed) => {
                let _ = termios.set_input_speed(arg);
            }
            Some(Mode::OutputSpeed) => {
                let _ = termios.set_output_speed(arg);
            }
            None => debug!(opcode = op, arg, "ignoring terminal mode"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_termios() -> Termios {
        // A real pty's defaults, so the test sees what children would.
        let request = PtyRequest {
            term: String::new(),
            size: WindowSize::default(),
            modes: bytes::Bytes::new(),
        };
        let terminal = Terminal::open(&request).unwrap();
        rustix::termios::tcgetattr(terminal.slave.as_ref().unwrap()).unwrap()
    }

    #[test]
    fn flags_chars_and_sizes() {
        let mut termios = default_termios();
        assert!(termios.local_modes.contains(LocalModes::ECHO));
        apply_modes(
            &mut termios,
            &modes::encode([
                (opcode::ECHO, 0),
                (opcode::IXANY, 1),
                (opcode::VINTR, 7),
                (opcode::VQUIT, DISABLED_CHAR),
                (opcode::CS7, 1),
                (opcode::VEOF, 0x1_0000), // nonsense: ignored
                (opcode::VSTATUS, 20),    // not on Linux: ignored
            ]),
        );
        assert!(!termios.local_modes.contains(LocalModes::ECHO));
        assert!(termios.input_modes.contains(InputModes::IXANY));
        assert_eq!(termios.special_codes[SpecialCodeIndex::VINTR], 7);
        assert_eq!(termios.special_codes[SpecialCodeIndex::VQUIT], 0);
        assert_eq!(termios.special_codes[SpecialCodeIndex::VEOF], 4); // ^D
        assert_eq!(
            termios.control_modes & ControlModes::CSIZE,
            ControlModes::CS7
        );
    }

    #[test]
    fn open_applies_size() {
        let request = PtyRequest {
            term: "xterm".into(),
            size: WindowSize {
                cols: 100,
                rows: 30,
                width_px: 0,
                height_px: 0,
            },
            modes: modes::encode([]),
        };
        let mut terminal = Terminal::open(&request).unwrap();
        assert!(terminal.path().starts_with("/dev/pts"));
        let size = rustix::termios::tcgetwinsize(&terminal.master).unwrap();
        assert_eq!((size.ws_col, size.ws_row), (100, 30));

        terminal
            .resize(WindowSize {
                cols: 70_000, // clamped
                rows: 10,
                width_px: 0,
                height_px: 0,
            })
            .unwrap();
        let size = rustix::termios::tcgetwinsize(&terminal.master).unwrap();
        assert_eq!((size.ws_col, size.ws_row), (u16::MAX, 10));
        terminal.close_slave();
        assert!(terminal.slave.is_none());
    }
}
