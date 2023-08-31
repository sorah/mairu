#[derive(clap::Parser)]
#[clap(author, version, long_about = None)]
#[clap(about = "Mairu TODO")]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Agent(mairu::cmd::agent::AgentArgs),
    Login(mairu::cmd::login::LoginArgs),
    ListSessions,
}

fn main() -> Result<(), anyhow::Error> {
    use clap::Parser;
    let cli = Cli::parse();

    enable_tracing(true); // TODO: move to cmd::*
    match &cli.command {
        Commands::Agent(args) => mairu::cmd::agent::run(args),
        Commands::Login(args) => mairu::cmd::login::run(args),
        _ => anyhow::bail!("Unknown command"), // TODO: remove this line
    }
}

fn enable_tracing(stderr: bool) {
    if let Ok(l) = std::env::var("MAIRU_LOG") {
        std::env::set_var("RUST_LOG", l);
    }
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "mairu=info");
    }

    if stderr {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        tracing_subscriber::fmt::init();
    }
}
