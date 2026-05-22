use clap::Parser;

mod cli;
mod cli_render;
mod error;

use cli::Cli;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    if let Err(error) = cli::run(cli).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
