use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use agentshield::config::Config;
use agentshield::output::OutputFormat;
use agentshield::rules::{RuleEngine, Severity};
use agentshield::ScanOptions;

#[derive(Parser)]
#[command(
    name = "agentshield",
    about = "Security scanner for AI agent extensions (MCP, OpenClaw, LangChain)",
    long_about = "AgentShield scans AI agent extensions for security vulnerabilities.\n\n\
                  It detects command injection, credential exfiltration, SSRF, arbitrary \
                  file access, supply chain issues, and more. Results can be output as \
                  console text, JSON, SARIF (GitHub Code Scanning), or HTML reports.",
    version,
    author
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan an agent extension for security issues
    Scan {
        /// Path to the extension directory
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Config file path
        #[arg(long, short = 'c')]
        config: Option<PathBuf>,

        /// Output format (console, json, sarif, html)
        #[arg(long, short = 'f', default_value = "console")]
        format: String,

        /// Minimum severity to fail (info, low, medium, high, critical)
        #[arg(long)]
        fail_on: Option<String>,

        /// Write output to file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Skip test files (test/, tests/, __tests__/, *.test.ts, *.spec.ts, etc.)
        #[arg(long)]
        ignore_tests: bool,
    },

    /// List all available detection rules
    ListRules {
        /// Output format (table, json)
        #[arg(long, short = 'f', default_value = "table")]
        format: String,
    },

    /// Generate a starter .agentshield.toml config file
    Init {
        /// Overwrite existing config file
        #[arg(long)]
        force: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan {
            path,
            config,
            format,
            fail_on,
            output,
            ignore_tests,
        } => cmd_scan(path, config, format, fail_on, output, ignore_tests),
        Commands::ListRules { format } => cmd_list_rules(format),
        Commands::Init { force } => cmd_init(force),
    };

    match result {
        Ok(exit_code) => process::exit(exit_code),
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(e.exit_code());
        }
    }
}

fn cmd_scan(
    path: PathBuf,
    config: Option<PathBuf>,
    format_str: String,
    fail_on_str: Option<String>,
    output_path: Option<PathBuf>,
    ignore_tests: bool,
) -> Result<i32, agentshield::error::ShieldError> {
    let format = OutputFormat::from_str_lenient(&format_str).unwrap_or_else(|| {
        eprintln!("Warning: unknown format '{}', using console", format_str);
        OutputFormat::Console
    });

    let fail_on = fail_on_str.and_then(|s| {
        let sev = Severity::from_str_lenient(&s);
        if sev.is_none() {
            eprintln!("Warning: unknown severity '{}', using config default", s);
        }
        sev
    });

    let options = ScanOptions {
        config_path: config,
        format,
        fail_on_override: fail_on,
        ignore_tests,
    };

    let report = agentshield::scan(&path, &options)?;
    let rendered = agentshield::render_report(&report, format)?;

    match output_path {
        Some(out) => std::fs::write(&out, &rendered)?,
        None => print!("{}", rendered),
    }

    // Exit code: 0 = pass, 1 = findings above threshold
    Ok(if report.verdict.pass { 0 } else { 1 })
}

fn cmd_list_rules(format_str: String) -> Result<i32, agentshield::error::ShieldError> {
    let engine = RuleEngine::new();
    let rules = engine.list_rules();

    match format_str.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&rules)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<12} {:<28} {:<10} {:<8} CATEGORY",
                "ID", "NAME", "SEVERITY", "CWE"
            );
            println!("{}", "-".repeat(80));
            for rule in &rules {
                println!(
                    "{:<12} {:<28} {:<10} {:<8} {}",
                    rule.id,
                    rule.name,
                    rule.default_severity.to_string(),
                    rule.cwe_id.as_deref().unwrap_or("-"),
                    rule.attack_category,
                );
            }
        }
    }

    Ok(0)
}

fn cmd_init(force: bool) -> Result<i32, agentshield::error::ShieldError> {
    let path = PathBuf::from(".agentshield.toml");

    if path.exists() && !force {
        eprintln!(".agentshield.toml already exists. Use --force to overwrite.");
        return Ok(1);
    }

    std::fs::write(&path, Config::starter_toml())?;
    println!("Created .agentshield.toml");

    Ok(0)
}
