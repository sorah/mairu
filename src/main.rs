shadow_rs::shadow!(build);

#[allow(clippy::const_is_empty)]
const VERSION: &str = if build::SHORT_COMMIT.is_empty() {
    build::PKG_VERSION
} else if build::GIT_CLEAN {
    shadow_rs::formatcp!("{} ({})", build::PKG_VERSION, build::SHORT_COMMIT)
} else {
    shadow_rs::formatcp!("{} ({}-dirty)", build::PKG_VERSION, build::SHORT_COMMIT)
};

#[derive(clap::Parser)]
#[clap(author, version = VERSION, long_about = None)]
#[clap(about = "Mairu: on-memory AWS credentials agent")]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Execute command with AWS credentials
    Exec(mairu::cmd::exec::ExecArgs),

    /// Login to your credential server
    Login(mairu::cmd::login::LoginArgs),
    /// Use Mairu as a credenital process provider
    CredentialProcess(mairu::cmd::credential_process::CredentialProcessArgs),
    /// List active sessions
    ListSessions(mairu::cmd::list_sessions::ListSessionsArgs),
    /// List available roles
    ListRoles(mairu::cmd::list_roles::ListRolesArgs),
    /// Refresh existing session
    Refresh(mairu::cmd::refresh::RefreshArgs),

    /// Show current 'auto' role
    Show(mairu::cmd::show::ShowArgs),

    /// Manually start agent process; it is automatically spawned when not present
    Agent(mairu::cmd::agent::AgentArgs),

    /// Instruct the agent to shut down
    KillAgent,

    /// Setup Mairu for your AWS SSO (AWS IAM Identity Center) instance
    SetupSso(mairu::cmd::setup_sso::SetupSsoArgs),

    /// Show how this mairu and the agent verify each other
    Doctor(mairu::cmd::doctor::DoctorArgs),

    /// Install a hardened copy of mairu for this host (run as root)
    Harden(mairu::cmd::harden::HardenArgs),

    /// Serve platform services to the parent agent; started only by the agent
    #[command(hide = true)]
    PlatformHelper {
        #[arg(long)]
        fd: std::os::fd::RawFd,
    },
}

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    mairu::hardening::Hardening::detect();
    #[cfg(target_os = "linux")]
    let suggest_hardening = mairu::hardening::reexec_hardened_if_available();

    use clap::Parser;
    let cli = Cli::parse();
    if let Commands::PlatformHelper { fd } = cli.command {
        return Ok(mairu::cmd::platform_helper::run(fd));
    }

    match &cli.command {
        Commands::Agent(a) => {
            if mairu::hardening::Hardening::marker().is_some() {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    mairu::hardening::sanitize_environment();
                }
            }
            if let Ok(l) = std::env::var("MAIRU_AGENT_LOG") {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    std::env::set_var("MAIRU_LOG", l);
                }
            }
            if a.log_to_file {
                enable_log(LogType::File)
            } else {
                enable_log(LogType::Custom);
            }
        }
        Commands::Exec(_) => enable_log(LogType::Custom),
        Commands::CredentialProcess(_) => enable_log(LogType::Custom),
        Commands::KillAgent => enable_log(LogType::Custom),
        Commands::Doctor(_) => enable_log(LogType::Custom),
        Commands::Harden(_) => enable_log(LogType::Custom),
        _ => enable_log(LogType::Default),
    }
    #[cfg(target_os = "linux")]
    if suggest_hardening && !matches!(cli.command, Commands::Agent(_)) {
        mairu::hardening::suggestion::maybe_show();
    }
    let retval = match &cli.command {
        Commands::Agent(args) => mairu::cmd::agent::run(args),
        Commands::Login(args) => mairu::cmd::login::run(args),
        Commands::CredentialProcess(args) => mairu::cmd::credential_process::run(args),
        Commands::ListSessions(args) => mairu::cmd::list_sessions::run(args),
        Commands::ListRoles(args) => mairu::cmd::list_roles::run(args),
        Commands::Refresh(args) => mairu::cmd::refresh::run(args),
        Commands::Show(args) => mairu::cmd::show::run(args),
        Commands::Exec(args) => mairu::cmd::exec::run(args),
        Commands::KillAgent => mairu::cmd::kill_agent::run(),
        Commands::SetupSso(args) => mairu::cmd::setup_sso::run(args),
        Commands::Doctor(args) => mairu::cmd::doctor::run(args),
        Commands::Harden(args) => mairu::cmd::harden::run(args),
        Commands::PlatformHelper { .. } => unreachable!(),
    };
    match retval {
        Ok(_) => Ok(std::process::ExitCode::SUCCESS),
        Err(e) => match e.downcast_ref::<mairu::Error>() {
            Some(mairu::Error::FailureButSilentlyExit) => Ok(std::process::ExitCode::FAILURE),
            Some(mairu::Error::SilentlyExitWithCode(c)) => Ok(*c),
            _ => match mairu::agent::authorization_error(&e) {
                Some(authz) => {
                    eprintln!("Error: the agent refused this request: {}", authz.detail);
                    Ok(std::process::ExitCode::FAILURE)
                }
                None => Err(e),
            },
        },
    }
}

enum LogType {
    Default,
    Custom,
    File,
}

fn enable_log(kind: LogType) {
    let rust_log = std::env::var_os("RUST_LOG");

    #[cfg(not(debug_assertions))]
    // SAFETY: Called during program initialization in single-threaded context
    // before any threads are spawned.
    unsafe {
        std::env::remove_var("RUST_LOG");
    }

    if let Ok(l) = std::env::var("MAIRU_LOG") {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::set_var("RUST_LOG", l);
        }
    }
    match kind {
        LogType::Default => {
            if std::env::var_os("RUST_LOG").is_none() {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    std::env::set_var("RUST_LOG", "mairu=info");
                }
            }
            tracing_subscriber::fmt::init();
        }
        LogType::Custom => {
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
        LogType::File => {
            if std::env::var_os("RUST_LOG").is_none() {
                // SAFETY: Called during program initialization in single-threaded context
                // before any threads are spawned.
                unsafe {
                    std::env::set_var("RUST_LOG", "mairu=info");
                }
            }
            let log_dir = mairu::config::log_dir_mkpath().expect("can't create log directory");
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
            let w = tracing_appender::rolling::daily(log_dir, "mairu.log");
            tracing_subscriber::fmt()
                .with_writer(w)
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .init();
        }
    }

    if let Some(v) = rust_log {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::set_var("RUST_LOG", v);
        }
    } else {
        // SAFETY: Called during program initialization in single-threaded context
        // before any threads are spawned.
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
    }
}
