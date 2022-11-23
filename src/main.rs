#![allow(warnings)]

use anyhow::Result;
use clap::Parser;
use clap_verbosity_flag::Verbosity;
use tracing::{debug, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

shadow_rs::shadow!(build);

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    // #[command(subcommand)]
    // action: Action,
    /// emacs-friendly output
    #[clap(long = "emacs", short = 'e', default_value = "false", global = true)]
    emacs: bool,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}
fn main() -> Result<()> {
    let args = Args::parse();
    debug!("args {:#?}", args);
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(convert_filter(args.verbose.log_level_filter())))
        .init();
    println!("Hello, world!");
    Ok(())
}

fn convert_filter(filter: log::LevelFilter) -> tracing_subscriber::filter::LevelFilter {
    match filter {
        log::LevelFilter::Off => tracing_subscriber::filter::LevelFilter::OFF,
        log::LevelFilter::Error => tracing_subscriber::filter::LevelFilter::ERROR,
        log::LevelFilter::Warn => tracing_subscriber::filter::LevelFilter::WARN,
        log::LevelFilter::Info => tracing_subscriber::filter::LevelFilter::INFO,
        log::LevelFilter::Debug => tracing_subscriber::filter::LevelFilter::DEBUG,
        log::LevelFilter::Trace => tracing_subscriber::filter::LevelFilter::TRACE,
    }
}
