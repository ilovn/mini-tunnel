//! Windows Service Control Manager entry point for a managed peer mesh.

use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use clap::Parser;
use serde::Deserialize;
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};
use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle};

const MAX_CONFIG_BYTES: u64 = 64 * 1024;
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

static SERVICE_NAME: OnceLock<String> = OnceLock::new();
static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();
static SHUTDOWN_RECEIVER: OnceLock<watch::Receiver<bool>> = OnceLock::new();

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    /// Safe, non-secret CLI arguments beginning with `--state-dir`.
    arguments: Vec<String>,
    log_file: PathBuf,
    status_listen: String,
    coordinator_ca: Option<PathBuf>,
}

define_windows_service!(ffi_service_main, windows_service_main);

pub fn start(service_name: &str, config_path: &Path) -> ExitCode {
    if !valid_service_name(service_name) {
        eprintln!("error: invalid Windows service name");
        return ExitCode::FAILURE;
    }
    if !config_path.is_absolute() {
        eprintln!("error: Windows service config path must be absolute");
        return ExitCode::FAILURE;
    }
    if SERVICE_NAME.set(service_name.to_owned()).is_err()
        || CONFIG_PATH.set(config_path.to_path_buf()).is_err()
    {
        eprintln!("error: Windows service host was initialized more than once");
        return ExitCode::FAILURE;
    }

    match service_dispatcher::start(service_name, ffi_service_main) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: could not connect to the Windows Service Control Manager: {error}");
            ExitCode::FAILURE
        }
    }
}

pub async fn shutdown_signal() -> io::Result<()> {
    match SHUTDOWN_RECEIVER.get() {
        Some(receiver) => wait_for_stop(receiver.clone()).await,
        None => std::future::pending().await,
    }
}

pub fn is_service_context() -> bool {
    SHUTDOWN_RECEIVER.get().is_some()
}

async fn wait_for_stop(mut receiver: watch::Receiver<bool>) -> io::Result<()> {
    if *receiver.borrow_and_update() {
        return Ok(());
    }
    loop {
        receiver.changed().await.map_err(|_| {
            io::Error::new(io::ErrorKind::BrokenPipe, "service stop channel closed")
        })?;
        if *receiver.borrow_and_update() {
            return Ok(());
        }
    }
}

fn windows_service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("Windows service host failed: {error}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service_name = SERVICE_NAME
        .get()
        .ok_or("service name was not initialized")?
        .clone();
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    SHUTDOWN_RECEIVER
        .set(shutdown_receiver)
        .map_err(|_| "service shutdown receiver was initialized more than once")?;

    let handler_sender = shutdown_sender.clone();
    let status_handle_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_status_handle = Arc::clone(&status_handle_slot);
    let event_handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Ok(status_handle) = handler_status_handle.lock()
                    && let Some(status_handle) = status_handle.as_ref()
                {
                    let _ = status_handle.set_service_status(service_status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        ServiceExitCode::NO_ERROR,
                        1,
                        Duration::from_secs(30),
                        None,
                    ));
                }
                handler_sender.send_replace(true);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(&service_name, event_handler)?;
    status_handle.set_service_status(service_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        ServiceExitCode::NO_ERROR,
        1,
        Duration::from_secs(30),
        None,
    ))?;
    if let Ok(mut slot) = status_handle_slot.lock() {
        *slot = Some(status_handle);
    }

    let result = run_configured_peer(&status_handle);
    report_stopped(&status_handle, result.is_err());
    result
}

fn run_configured_peer(
    status_handle: &ServiceStatusHandle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = CONFIG_PATH.get().ok_or("config path was not initialized")?;
    let config = read_config(config_path)?;
    redirect_standard_output(&config.log_file)?;
    let state_dir = config
        .arguments
        .get(1)
        .ok_or("service config is missing its state directory")?;
    // Set before Clap resolves environment-backed CLI defaults and before peer startup.
    unsafe {
        std::env::set_var("MINI_TUNNEL_STATE_DIR", state_dir);
        std::env::set_var("MINI_TUNNEL_STATUS_LISTEN", &config.status_listen);
        if let Some(ca_path) = &config.coordinator_ca {
            std::env::set_var("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE", ca_path);
        } else {
            std::env::remove_var("MINI_TUNNEL_COORDINATOR_CA_CERT_FILE");
        }
        std::env::remove_var("MINI_TUNNEL_RELAY_SERVER");
        std::env::remove_var("MINI_TUNNEL_UDP_RELAY_SERVER");
        std::env::remove_var("MINI_TUNNEL_RELAY_STANDBY");
    }

    let mut arguments = vec![OsString::from("mini-tunnel")];
    arguments.extend(config.arguments.iter().map(OsString::from));
    let cli = super::Cli::try_parse_from(arguments)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    status_handle.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
        0,
        Duration::default(),
        Some(std::process::id()),
    ))?;

    if let Err(error) = runtime.block_on(super::run(cli)) {
        eprintln!("peer tunnel stopped with an error: {error}");
        return Err(error);
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<ServiceConfig, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err("service config must be a regular file no larger than 64 KiB".into());
    }
    let config: ServiceConfig = serde_json::from_slice(&fs::read(path)?)?;
    if config.arguments.len() < 2 || config.arguments.len() > 64 {
        return Err("service config must contain between 2 and 64 CLI arguments".into());
    }
    if contains_secret_argument_flag(&config.arguments) {
        return Err("service config must not contain invites, tokens, or passwords".into());
    }
    if config.arguments.first().map(String::as_str) != Some("--state-dir")
        || config.arguments.get(2).map(String::as_str) != Some("peer")
        || config.arguments.get(3).map(String::as_str) != Some("tunnel")
        || config.arguments.get(4).map(String::as_str) != Some("mesh")
    {
        return Err("service config must start with --state-dir and run peer tunnel mesh".into());
    }
    if !Path::new(&config.arguments[1]).is_absolute() {
        return Err("service state directory must be absolute".into());
    }
    let status_address = config.status_listen.parse::<std::net::SocketAddr>()?;
    if !status_address.ip().is_loopback() || status_address.port() == 0 {
        return Err("service status listener must use a fixed loopback port".into());
    }
    if config
        .coordinator_ca
        .as_ref()
        .is_some_and(|path| !path.is_absolute() || !path.is_file())
    {
        return Err("service Coordinator CA path must be an existing absolute file".into());
    }
    if !config.log_file.is_absolute() {
        return Err("service log path must be absolute".into());
    }
    Ok(config)
}

fn redirect_standard_output(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    rotate_log(path)?;
    let log_file = OpenOptions::new().create(true).append(true).open(path)?;
    let handle = log_file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: the file remains open for the service process lifetime and the standard handles
    // are only used for writes by this process.
    let stdout_ok = unsafe { SetStdHandle(STD_OUTPUT_HANDLE, handle) };
    // SAFETY: same live file handle, intentionally shared by stdout and stderr.
    let stderr_ok = unsafe { SetStdHandle(STD_ERROR_HANDLE, handle) };
    if stdout_ok == 0 || stderr_ok == 0 {
        return Err(io::Error::last_os_error());
    }
    std::mem::forget(log_file);
    Ok(())
}

fn rotate_log(path: &Path) -> io::Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service log must be a regular file",
        ));
    }
    if metadata.len() < MAX_LOG_BYTES {
        return Ok(());
    }
    let rotated = path.with_extension("log.1");
    if rotated.exists() {
        fs::remove_file(&rotated)?;
    }
    fs::rename(path, rotated)
}

fn report_stopped(status_handle: &ServiceStatusHandle, failed: bool) {
    let exit_code = if failed {
        ServiceExitCode::ServiceSpecific(1)
    } else {
        ServiceExitCode::NO_ERROR
    };
    let status = service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
        0,
        Duration::default(),
        None,
    );
    let _ = status_handle.set_service_status(status);
}

fn service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
    checkpoint: u32,
    wait_hint: Duration,
    process_id: Option<u32>,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id,
    }
}

fn valid_service_name(name: &str) -> bool {
    (1..=80).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn contains_secret_argument_flag(arguments: &[String]) -> bool {
    arguments.iter().any(|argument| {
        let value = argument.to_ascii_lowercase();
        argument.starts_with("--")
            && (value.contains("token") || value.contains("invite") || value.contains("password"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_bounded_and_scm_safe() {
        assert!(valid_service_name("mini-tunnel-peer-office_1"));
        assert!(!valid_service_name(""));
        assert!(!valid_service_name("mini tunnel"));
        assert!(!valid_service_name("x".repeat(81).as_str()));
    }

    #[tokio::test]
    async fn service_stop_signal_wakes_shutdown_waiter() {
        let (sender, receiver) = watch::channel(false);
        let waiter = tokio::spawn(wait_for_stop(receiver));
        sender.send_replace(true);
        waiter
            .await
            .expect("shutdown waiter task")
            .expect("stop signal");
    }

    #[test]
    fn runtime_config_rejects_invite_material() {
        let config = serde_json::json!({
            "arguments": ["--state-dir", "C:/ProgramData/mini-tunnel/test", "peer", "tunnel", "mesh", "--invite-token-file", "C:/secret"],
            "log_file": "C:/ProgramData/mini-tunnel/test/service.log",
            "status_listen": "127.0.0.1:42003",
            "coordinator_ca": null
        });
        let path = std::env::temp_dir().join(format!(
            "mini-tunnel-service-config-test-{}.json",
            std::process::id()
        ));
        fs::write(&path, config.to_string()).expect("write service config");
        let error = read_config(&path).expect_err("invite arguments must be rejected");
        let _ = fs::remove_file(&path);
        assert!(error.to_string().contains("must not contain invites"));
    }

    #[test]
    fn coordinator_urls_may_contain_invite_as_a_path_word() {
        let arguments = [
            "--state-dir",
            "C:/ProgramData/mini-tunnel/test",
            "peer",
            "tunnel",
            "mesh",
            "--coordinator-url",
            "https://coordinator.example/invite/api",
        ]
        .map(str::to_owned);
        assert!(!contains_secret_argument_flag(&arguments));
    }

    #[test]
    fn oversized_service_log_rotates_on_startup() {
        let directory = std::env::temp_dir().join(format!(
            "mini-tunnel-service-log-test-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&directory).expect("create log test directory");
        let path = directory.join("service.log");
        fs::write(&path, vec![b'x'; MAX_LOG_BYTES as usize + 1]).expect("write oversized log");

        rotate_log(&path).expect("rotate oversized log");

        assert!(!path.exists());
        assert_eq!(
            fs::metadata(directory.join("service.log.1"))
                .expect("rotated log")
                .len(),
            MAX_LOG_BYTES + 1
        );
        fs::remove_dir_all(directory).expect("clean log test directory");
    }
}
