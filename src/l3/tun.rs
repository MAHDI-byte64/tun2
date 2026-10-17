//! The TUN / TAP device of an l3 tunnel (`kz0`, `kz1`, ...): created on start with its
//! addresses and MTU set, torn down on stop. Linux only, `/dev/net/tun` + `CAP_NET_ADMIN`.
//!
//! `layer = 3` makes a TUN device carrying whole IP packets; `layer = 2` makes a TAP
//! device carrying Ethernet frames (an encrypted GRETAP). The device is created with the
//! `TUNSETIFF` ioctl (via the nix crate) and brought up / addressed with the `ip`
//! iproute2 command — no netlink crate is pulled in. A device made this way is owned by
//! the open file descriptor and removed by the kernel when it is closed, so dropping
//! [`TunDevice`] tears the interface down (RAII), and the addresses go with it.

use std::io;

/// IP packets (TUN) or Ethernet frames (TAP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// `layer = 3`: a TUN device, whole IP packets.
    Ip,
    /// `layer = 2`: a TAP device, whole Ethernet frames (GRETAP).
    Ethernet,
}

impl Layer {
    /// From the `[l3] layer` value (validated to 2 or 3 already).
    pub fn from_config(layer: u8) -> Self {
        if layer == 2 {
            Self::Ethernet
        } else {
            Self::Ip
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "layer3/TUN",
            Self::Ethernet => "layer2/TAP",
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::TunDevice;

#[cfg(not(target_os = "linux"))]
pub use other::TunDevice;

/// The parameters a device is created with.
pub struct DeviceConfig<'a> {
    /// The requested interface name, or `None` to pick the next free `kzN`.
    pub iface: Option<&'a str>,
    pub layer: Layer,
    /// This end's address as a CIDR (`10.10.0.1/30`); `None` leaves the device address-less
    /// (layer 2 bridging).
    pub local_ip: Option<&'a str>,
    pub mtu: u16,
}

#[cfg(not(target_os = "linux"))]
mod other {
    use super::{DeviceConfig, Layer};
    use std::io;

    /// Placeholder on non-Linux targets: creation always refuses.
    pub enum TunDevice {}

    impl TunDevice {
        pub fn create(_config: &DeviceConfig<'_>) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the l3 / GRE tunnel is Linux only (needs /dev/net/tun and CAP_NET_ADMIN)",
            ))
        }

        pub fn name(&self) -> &str {
            match *self {}
        }

        pub fn layer(&self) -> Layer {
            match *self {}
        }

        pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
            match *self {}
        }

        pub async fn send(&self, _packet: &[u8]) -> io::Result<()> {
            match *self {}
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{DeviceConfig, Layer};
    use std::ffi::OsStr;
    use std::io;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::process::Command;

    use nix::libc;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use tracing::debug;

    // `TUNSETIFF` encodes the size of a C `int`, not of the `ifreq` it is actually passed,
    // so it is a "bad" ioctl: the request code is given literally and the data type is
    // `ifreq`. The generated `tunsetiff(fd, *const ifreq)` sets the interface up.
    nix::ioctl_write_ptr_bad!(tunsetiff, libc::TUNSETIFF, libc::ifreq);

    /// How many `kzN` names to try before giving up when no name was configured.
    const MAX_IFACE_INDEX: u32 = 256;

    /// An open TUN/TAP device: the fd owns the interface, which the kernel removes when the
    /// fd closes (RAII). Reads and writes are made non-blocking and driven by tokio.
    pub struct TunDevice {
        fd: AsyncFd<OwnedFd>,
        name: String,
        layer: Layer,
    }

    impl TunDevice {
        /// Creates and brings up the device. Picks the next free `kzN` when no name was
        /// given. Fails with [`io::ErrorKind::PermissionDenied`] mapped to a clear message
        /// when `/dev/net/tun` cannot be opened without privileges.
        pub fn create(config: &DeviceConfig<'_>) -> io::Result<Self> {
            match &config.iface {
                Some(name) => Self::create_named(name, config),
                None => {
                    let mut last = None;
                    for i in 0..MAX_IFACE_INDEX {
                        let name = format!("kz{i}");
                        match Self::create_named(&name, config) {
                            Ok(dev) => return Ok(dev),
                            // The name is taken: try the next index.
                            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                                last = Some(e);
                                continue;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(last.unwrap_or_else(|| {
                        io::Error::other("no free kzN interface name was available")
                    }))
                }
            }
        }

        fn create_named(name: &str, config: &DeviceConfig<'_>) -> io::Result<Self> {
            if name.len() > 15 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "interface name is too long (max 15 characters)",
                ));
            }
            let fd = open_tun()?;
            let flags = match config.layer {
                // IFF_NO_PI: no 4-byte packet-info prefix, so a read is exactly one packet.
                Layer::Ip => libc::IFF_TUN | libc::IFF_NO_PI,
                Layer::Ethernet => libc::IFF_TAP | libc::IFF_NO_PI,
            };
            // SAFETY: a zeroed `ifreq` is valid; the name is written within bounds and the
            // flags field is set before the ioctl reads it.
            let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
            for (slot, byte) in ifr.ifr_name.iter_mut().zip(name.bytes()) {
                *slot = byte as libc::c_char;
            }
            ifr.ifr_ifru.ifru_flags = flags as libc::c_short;
            // SAFETY: `fd` is a live descriptor to /dev/net/tun and `ifr` is a valid ifreq.
            unsafe { tunsetiff(fd.as_raw_fd(), &ifr) }
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

            let dev = Self {
                fd: AsyncFd::with_interest(fd, Interest::READABLE | Interest::WRITABLE)?,
                name: name.to_owned(),
                layer: config.layer,
            };
            dev.configure(config)?;
            Ok(dev)
        }

        /// Brings the interface up, sets its MTU and assigns its address (if any) with the
        /// `ip` command.
        fn configure(&self, config: &DeviceConfig<'_>) -> io::Result<()> {
            let mtu = config.mtu.to_string();
            ip(&["link", "set", "dev", &self.name, "mtu", &mtu, "up"])?;
            if let Some(local_ip) = config.local_ip {
                // A /30 (or any prefix covering the peer) makes the peer reachable over the
                // connected route, so no explicit peer route is needed.
                ip(&["addr", "add", local_ip, "dev", &self.name])?;
            }
            Ok(())
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn layer(&self) -> Layer {
            self.layer
        }

        /// Reads one whole IP packet (TUN) or Ethernet frame (TAP) from the interface.
        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let raw = self.fd.get_ref().as_raw_fd();
            loop {
                let mut guard = self.fd.readable().await?;
                match guard.try_io(|_| read(raw, buf)) {
                    Ok(result) => return result,
                    Err(_would_block) => continue,
                }
            }
        }

        /// Writes one whole IP packet (TUN) or Ethernet frame (TAP) to the interface.
        pub async fn send(&self, packet: &[u8]) -> io::Result<()> {
            let raw = self.fd.get_ref().as_raw_fd();
            loop {
                let mut guard = self.fd.writable().await?;
                match guard.try_io(|_| write(raw, packet)) {
                    Ok(result) => return result.map(|_| ()),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl Drop for TunDevice {
        fn drop(&mut self) {
            // The kernel removes the interface when the fd closes; the address goes with
            // it. This is only a best-effort tidy-up for any lingering state.
            debug!(iface = %self.name, "l3 device closed");
        }
    }

    /// Opens `/dev/net/tun` read-write and non-blocking.
    fn open_tun() -> io::Result<OwnedFd> {
        use std::os::fd::FromRawFd;
        // SAFETY: a plain open; the returned fd is wrapped in an OwnedFd that closes it.
        let fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(match e.kind() {
                io::ErrorKind::PermissionDenied => io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the l3 / GRE tunnel needs root (or CAP_NET_ADMIN) to open /dev/net/tun",
                ),
                _ => e,
            });
        }
        // SAFETY: `fd` is a freshly opened, owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn read(fd: libc::c_int, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid writable slice of the given length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn write(fd: libc::c_int, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: `buf` is a valid readable slice of the given length.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Runs `ip <args>`, mapping a failure to an error that names the command and reason.
    /// Finds the binary on `PATH` or in the usual sbin directories (iproute2 often lives
    /// in `/usr/sbin`, which is not always on a service's `PATH`).
    fn ip(args: &[&str]) -> io::Result<()> {
        let output = Command::new(ip_binary())
            .args(args)
            .output()
            .map_err(|e| io::Error::new(e.kind(), format!("could not run `ip`: {e}")))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )))
    }

    /// The `ip` binary to run.
    fn ip_binary() -> PathBuf {
        for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
            let candidate = PathBuf::from(dir).join("ip");
            if candidate.exists() {
                return candidate;
            }
        }
        // Fall back to a bare name so `PATH` is consulted.
        PathBuf::from(OsStr::from_bytes(b"ip"))
    }
}

/// Whether the host can run an l3 tunnel at all (Linux with `/dev/net/tun` and `ip`).
/// Used to refuse early with a clear message instead of failing mid-setup.
pub fn host_supports_l3() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !std::path::Path::new("/dev/net/tun").exists() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the l3 / GRE tunnel needs /dev/net/tun (load the `tun` kernel module)",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the l3 / GRE tunnel is Linux only (needs /dev/net/tun and CAP_NET_ADMIN)",
        ))
    }
}
