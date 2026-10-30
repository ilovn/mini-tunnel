//! Explicit, narrowly scoped host-route management for peer tunnels.

use std::{
    ffi::OsString,
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    pin::Pin,
    process::Output,
    time::Duration,
};

use thiserror::Error;

const ROUTE_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPlatform {
    Linux,
    MacOs,
    Windows,
    Unsupported,
}

impl RoutingPlatform {
    #[must_use]
    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }
        #[cfg(target_os = "macos")]
        {
            return Self::MacOs;
        }
        #[cfg(target_os = "windows")]
        {
            return Self::Windows;
        }
        #[allow(unreachable_code)]
        Self::Unsupported
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommand {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteAction {
    Add,
    Delete,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("automatic peer routes are supported only on Linux, macOS, and Windows")]
    UnsupportedPlatform,
    #[error("TUN interface name is empty, too long, or contains a NUL byte")]
    InvalidInterface,
    #[error("could not execute route command: {0}")]
    Io(#[from] io::Error),
    #[error("route command timed out ({operation}) after {timeout:?}")]
    CommandTimedOut {
        operation: &'static str,
        timeout: Duration,
    },
    #[error("route command failed ({operation}): {detail}")]
    CommandFailed {
        operation: &'static str,
        detail: String,
    },
}

/// Injectable process boundary. Unit tests use a fake and never touch host routes.
pub trait RouteRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        command: &'a RouteCommand,
    ) -> Pin<Box<dyn Future<Output = io::Result<Output>> + Send + 'a>>;
}

#[derive(Debug, Default)]
pub struct SystemRouteRunner;

impl RouteRunner for SystemRouteRunner {
    fn run<'a>(
        &'a self,
        command: &'a RouteCommand,
    ) -> Pin<Box<dyn Future<Output = io::Result<Output>> + Send + 'a>> {
        Box::pin(async move {
            tokio::process::Command::new(&command.program)
                .args(&command.args)
                .kill_on_drop(true)
                .output()
                .await
        })
    }
}

/// A lease exists only after this process successfully added the route.
#[derive(Debug, Clone)]
pub struct RouteLease {
    remove: RouteCommand,
}

impl RouteLease {
    /// Delete the exact host route created by this process.
    pub async fn remove(self, runner: &dyn RouteRunner) -> Result<(), RouteError> {
        execute(runner, &self.remove, "delete").await
    }
}

/// Install one peer `/32` route and return a lease that can remove that exact route.
pub async fn install_peer_route(
    runner: &dyn RouteRunner,
    platform: RoutingPlatform,
    interface: &str,
    peer: Ipv4Addr,
) -> Result<RouteLease, RouteError> {
    validate_interface(interface)?;
    let add = build_command(platform, RouteAction::Add, interface, peer)?;
    let remove = build_command(platform, RouteAction::Delete, interface, peer)?;
    execute(runner, &add, "add").await?;
    Ok(RouteLease { remove })
}

/// Install one peer `/128` IPv6 route and return a lease for that exact route.
pub async fn install_peer_ipv6_route(
    runner: &dyn RouteRunner,
    platform: RoutingPlatform,
    interface: &str,
    peer: Ipv6Addr,
) -> Result<RouteLease, RouteError> {
    validate_interface(interface)?;
    let add = build_ipv6_command(platform, RouteAction::Add, interface, peer)?;
    let remove = build_ipv6_command(platform, RouteAction::Delete, interface, peer)?;
    execute(runner, &add, "add").await?;
    Ok(RouteLease { remove })
}

fn validate_interface(interface: &str) -> Result<(), RouteError> {
    if interface.is_empty() || interface.len() > 64 || interface.as_bytes().contains(&0) {
        return Err(RouteError::InvalidInterface);
    }
    Ok(())
}

fn build_command(
    platform: RoutingPlatform,
    action: RouteAction,
    interface: &str,
    peer: Ipv4Addr,
) -> Result<RouteCommand, RouteError> {
    let (program, args) = match platform {
        RoutingPlatform::Linux => {
            let action = match action {
                RouteAction::Add => "add",
                RouteAction::Delete => "del",
            };
            (
                PathBuf::from("ip"),
                vec![
                    "-4".into(),
                    "route".into(),
                    action.into(),
                    format!("{peer}/32").into(),
                    "dev".into(),
                    interface.into(),
                ],
            )
        }
        RoutingPlatform::MacOs => {
            let action = match action {
                RouteAction::Add => "add",
                RouteAction::Delete => "delete",
            };
            (
                PathBuf::from("/sbin/route"),
                vec![
                    "-n".into(),
                    action.into(),
                    "-host".into(),
                    peer.to_string().into(),
                    "-interface".into(),
                    interface.into(),
                ],
            )
        }
        RoutingPlatform::Windows => (
            PathBuf::from("netsh"),
            vec![
                "interface".into(),
                "ipv4".into(),
                match action {
                    RouteAction::Add => "add".into(),
                    RouteAction::Delete => "delete".into(),
                },
                "route".into(),
                format!("{peer}/32").into(),
                format!("interface={interface}").into(),
                "store=active".into(),
            ],
        ),
        RoutingPlatform::Unsupported => return Err(RouteError::UnsupportedPlatform),
    };
    Ok(RouteCommand { program, args })
}

fn build_ipv6_command(
    platform: RoutingPlatform,
    action: RouteAction,
    interface: &str,
    peer: Ipv6Addr,
) -> Result<RouteCommand, RouteError> {
    let (program, args) = match platform {
        RoutingPlatform::Linux => {
            let action = match action {
                RouteAction::Add => "add",
                RouteAction::Delete => "del",
            };
            (
                PathBuf::from("ip"),
                vec![
                    "-6".into(),
                    "route".into(),
                    action.into(),
                    format!("{peer}/128").into(),
                    "dev".into(),
                    interface.into(),
                ],
            )
        }
        RoutingPlatform::MacOs => {
            let action = match action {
                RouteAction::Add => "add",
                RouteAction::Delete => "delete",
            };
            (
                PathBuf::from("/sbin/route"),
                vec![
                    "-n".into(),
                    action.into(),
                    "-inet6".into(),
                    format!("{peer}/128").into(),
                    "-interface".into(),
                    interface.into(),
                ],
            )
        }
        RoutingPlatform::Windows => (
            PathBuf::from("netsh"),
            vec![
                "interface".into(),
                "ipv6".into(),
                match action {
                    RouteAction::Add => "add".into(),
                    RouteAction::Delete => "delete".into(),
                },
                "route".into(),
                format!("{peer}/128").into(),
                format!("interface={interface}").into(),
                "store=active".into(),
            ],
        ),
        RoutingPlatform::Unsupported => return Err(RouteError::UnsupportedPlatform),
    };
    Ok(RouteCommand { program, args })
}

async fn execute(
    runner: &dyn RouteRunner,
    command: &RouteCommand,
    operation: &'static str,
) -> Result<(), RouteError> {
    execute_with_timeout(runner, command, operation, ROUTE_COMMAND_TIMEOUT).await
}

async fn execute_with_timeout(
    runner: &dyn RouteRunner,
    command: &RouteCommand,
    operation: &'static str,
    timeout: Duration,
) -> Result<(), RouteError> {
    let output = tokio::time::timeout(timeout, runner.run(command))
        .await
        .map_err(|_| RouteError::CommandTimedOut { operation, timeout })??;
    if output.status.success() {
        return Ok(());
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let detail = if detail.is_empty() {
        format!("process exited with {}", output.status)
    } else {
        detail
    };
    Err(RouteError::CommandFailed { operation, detail })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    #[cfg(unix)]
    fn exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status(code: i32) -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if code == 0 { 0 } else { 1 })
    }

    use super::*;

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<RouteCommand>>,
        statuses: Mutex<Vec<i32>>,
    }

    impl FakeRunner {
        fn with_statuses(statuses: &[i32]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                statuses: Mutex::new(statuses.iter().rev().copied().collect()),
            }
        }

        fn calls(&self) -> Vec<RouteCommand> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl RouteRunner for FakeRunner {
        fn run<'a>(
            &'a self,
            command: &'a RouteCommand,
        ) -> Pin<Box<dyn Future<Output = io::Result<Output>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().expect("calls lock").push(command.clone());
                let code = self
                    .statuses
                    .lock()
                    .expect("statuses lock")
                    .pop()
                    .unwrap_or(0);
                Ok(Output {
                    status: exit_status(code),
                    stdout: Vec::new(),
                    stderr: if code == 0 {
                        Vec::new()
                    } else {
                        b"route conflict or insufficient permission".to_vec()
                    },
                })
            })
        }
    }

    struct StalledRunner;

    impl RouteRunner for StalledRunner {
        fn run<'a>(
            &'a self,
            _command: &'a RouteCommand,
        ) -> Pin<Box<dyn Future<Output = io::Result<Output>> + Send + 'a>> {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn linux_add_and_remove_use_exact_peer_host_route() {
        let runner = FakeRunner::default();
        let lease = install_peer_route(
            &runner,
            RoutingPlatform::Linux,
            "tun7",
            Ipv4Addr::new(10, 77, 0, 3),
        )
        .await
        .expect("install route");
        lease.remove(&runner).await.expect("remove route");
        assert_eq!(
            runner.calls(),
            vec![
                RouteCommand {
                    program: "ip".into(),
                    args: ["-4", "route", "add", "10.77.0.3/32", "dev", "tun7"]
                        .map(OsString::from)
                        .to_vec(),
                },
                RouteCommand {
                    program: "ip".into(),
                    args: ["-4", "route", "del", "10.77.0.3/32", "dev", "tun7"]
                        .map(OsString::from)
                        .to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn ipv6_routes_use_peer_host_prefix_and_are_removed_by_lease() {
        let runner = FakeRunner::default();
        let peer: Ipv6Addr = "fd12:3456::3".parse().unwrap();
        let lease = install_peer_ipv6_route(&runner, RoutingPlatform::Linux, "tun7", peer)
            .await
            .expect("install IPv6 route");
        lease.remove(&runner).await.expect("remove IPv6 route");
        assert_eq!(
            runner.calls(),
            vec![
                RouteCommand {
                    program: "ip".into(),
                    args: ["-6", "route", "add", "fd12:3456::3/128", "dev", "tun7"]
                        .map(OsString::from)
                        .to_vec(),
                },
                RouteCommand {
                    program: "ip".into(),
                    args: ["-6", "route", "del", "fd12:3456::3/128", "dev", "tun7"]
                        .map(OsString::from)
                        .to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn windows_routes_use_active_netsh_host_routes_scoped_to_tun_alias() {
        let runner = FakeRunner::default();
        let lease = install_peer_route(
            &runner,
            RoutingPlatform::Windows,
            "mini tunnel",
            Ipv4Addr::new(10, 77, 0, 3),
        )
        .await
        .expect("install Windows IPv4 route");
        lease
            .remove(&runner)
            .await
            .expect("remove Windows IPv4 route");
        let ipv6_lease = install_peer_ipv6_route(
            &runner,
            RoutingPlatform::Windows,
            "mini tunnel",
            "fd12:3456::3".parse().unwrap(),
        )
        .await
        .expect("install Windows IPv6 route");
        ipv6_lease
            .remove(&runner)
            .await
            .expect("remove Windows IPv6 route");
        let command = |family: &str, action: &str, prefix: &str| RouteCommand {
            program: "netsh".into(),
            args: [
                "interface".into(),
                family.into(),
                action.into(),
                "route".into(),
                prefix.into(),
                "interface=mini tunnel".into(),
                "store=active".into(),
            ]
            .to_vec(),
        };
        assert_eq!(
            runner.calls(),
            vec![
                command("ipv4", "add", "10.77.0.3/32"),
                command("ipv4", "delete", "10.77.0.3/32"),
                command("ipv6", "add", "fd12:3456::3/128"),
                command("ipv6", "delete", "fd12:3456::3/128"),
            ]
        );
    }

    #[tokio::test]
    async fn macos_ipv6_host_route_is_bound_to_tun_interface() {
        let runner = FakeRunner::default();
        let lease = install_peer_ipv6_route(
            &runner,
            RoutingPlatform::MacOs,
            "utun8",
            "fd12:3456::3".parse().unwrap(),
        )
        .await
        .expect("install IPv6 route");
        lease.remove(&runner).await.expect("remove IPv6 route");
        assert_eq!(
            runner.calls(),
            vec![
                RouteCommand {
                    program: "/sbin/route".into(),
                    args: [
                        "-n",
                        "add",
                        "-inet6",
                        "fd12:3456::3/128",
                        "-interface",
                        "utun8"
                    ]
                    .map(OsString::from)
                    .to_vec(),
                },
                RouteCommand {
                    program: "/sbin/route".into(),
                    args: [
                        "-n",
                        "delete",
                        "-inet6",
                        "fd12:3456::3/128",
                        "-interface",
                        "utun8"
                    ]
                    .map(OsString::from)
                    .to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn macos_uses_host_route_bound_to_tun_interface() {
        let runner = FakeRunner::default();
        let lease = install_peer_route(
            &runner,
            RoutingPlatform::MacOs,
            "utun8",
            Ipv4Addr::new(10, 1, 2, 3),
        )
        .await
        .expect("install route");
        lease.remove(&runner).await.expect("remove route");
        assert_eq!(
            runner.calls(),
            vec![
                RouteCommand {
                    program: "/sbin/route".into(),
                    args: ["-n", "add", "-host", "10.1.2.3", "-interface", "utun8"]
                        .map(OsString::from)
                        .to_vec(),
                },
                RouteCommand {
                    program: "/sbin/route".into(),
                    args: ["-n", "delete", "-host", "10.1.2.3", "-interface", "utun8"]
                        .map(OsString::from)
                        .to_vec(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn failed_add_never_creates_lease_or_attempts_delete() {
        let runner = FakeRunner::with_statuses(&[2]);
        let result = install_peer_route(
            &runner,
            RoutingPlatform::Linux,
            "tun7",
            Ipv4Addr::new(10, 77, 0, 3),
        )
        .await;
        assert!(matches!(
            result,
            Err(RouteError::CommandFailed {
                operation: "add",
                ..
            })
        ));
        assert_eq!(runner.calls().len(), 1);
    }

    #[tokio::test]
    async fn stalled_route_command_returns_timeout_error() {
        let command = RouteCommand {
            program: "ip".into(),
            args: ["-4", "route", "add", "10.77.0.3/32"]
                .map(OsString::from)
                .to_vec(),
        };
        let error =
            execute_with_timeout(&StalledRunner, &command, "add", Duration::from_millis(10))
                .await
                .unwrap_err();

        assert!(matches!(
            error,
            RouteError::CommandTimedOut {
                operation: "add",
                timeout
            } if timeout == Duration::from_millis(10)
        ));
    }

    #[tokio::test]
    async fn unsupported_platform_and_invalid_interface_run_no_command() {
        let runner = FakeRunner::default();
        let result = install_peer_route(
            &runner,
            RoutingPlatform::Unsupported,
            "tun7",
            Ipv4Addr::new(10, 77, 0, 3),
        )
        .await;
        assert!(matches!(result, Err(RouteError::UnsupportedPlatform)));
        let result = install_peer_route(
            &runner,
            RoutingPlatform::Linux,
            "",
            Ipv4Addr::new(10, 77, 0, 3),
        )
        .await;
        assert!(matches!(result, Err(RouteError::InvalidInterface)));
        assert!(runner.calls().is_empty());
    }
}
