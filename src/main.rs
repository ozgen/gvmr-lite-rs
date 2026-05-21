use clap::Parser;

use gvmr_lite_rs::{cli::Cli, run_cli_or_server};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(error) = run_cli_or_server(cli).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
