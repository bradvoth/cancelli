//! Thin CLI over the `cancelli` library (D8).

use std::io::{Read, Write};
use std::process::ExitCode;

use cancelli::config::{self, CliOverrides, Env};
use cancelli::engine::{self, Options};
use cancelli::hook::{self, HookArgs};
use cancelli::policy::Mode;
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "cancelli",
    version,
    about = "CARE shell-command risk analysis as a Claude Code PreToolUse hook"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum ModeArg {
    Strict,
    Balanced,
    Auto,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Strict => Mode::Strict,
            ModeArg::Balanced => Mode::Balanced,
            ModeArg::Auto => Mode::Auto,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Read a PreToolUse payload on stdin, log it, and (unless --dry-run)
    /// print a permission decision.
    Hook {
        /// Never print a decision (always exit 0 with empty stdout).
        #[arg(long)]
        dry_run: bool,
        /// Operating mode (thresholds).
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
        /// A Jev "allow" emits permissionDecision "allow" (D13).
        #[arg(long)]
        decide_all: bool,
    },
    /// Ask Jev about one command and print the judge record as JSON.
    Judge {
        /// The shell command.
        command: String,
        /// Session transcript (JSONL) for the user request and prior actions.
        #[arg(long)]
        transcript: Option<std::path::PathBuf>,
        /// User request text (replaces the transcript's prompts).
        #[arg(long)]
        request: Option<String>,
        /// Show `would_emit` as with --decide-all.
        #[arg(long)]
        decide_all: bool,
    },
    /// Print the full analysis of one command as JSON.
    Analyze {
        /// The shell command.
        command: String,
        /// Operating mode (thresholds).
        #[arg(long, value_enum)]
        mode: Option<ModeArg>,
    },
    /// Print the effective configuration and where each value came from.
    Config {
        /// Write a commented default config file (never overwrites).
        #[arg(long)]
        init: bool,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // In hook context a bad flag must not break the session.
            let hook_invocation = std::env::args().nth(1).as_deref() == Some("hook");
            let _ = e.print();
            return if hook_invocation || !e.use_stderr() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            };
        }
    };
    match cli.cmd {
        Cmd::Hook {
            dry_run,
            mode,
            decide_all,
        } => {
            // Fail open on panics too: silence the default panic message and
            // log an error record instead.
            std::panic::set_hook(Box::new(|_| {}));
            let env = Env::from_process();
            let args = HookArgs {
                dry_run,
                mode: mode.map(Mode::from),
                decide_all,
            };
            let mut stdin = Vec::new();
            let read = std::io::stdin().read_to_end(&mut stdin);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match read {
                Ok(_) => hook::run(&stdin, &args, &env),
                Err(e) => {
                    let loaded = hook::load_config(&env, &args);
                    hook::log_error(&loaded, "read_stdin", &e.to_string(), Default::default());
                    hook::HookOutput {
                        stdout: String::new(),
                    }
                }
            }));
            match result {
                Ok(out) => {
                    if !out.stdout.is_empty() {
                        let _ = writeln!(std::io::stdout(), "{}", out.stdout);
                    }
                }
                Err(p) => {
                    let msg = p
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| p.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "panic".into());
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let loaded = hook::load_config(&env, &args);
                        hook::log_error(&loaded, "panic", &msg, Default::default());
                    }));
                }
            }
            ExitCode::SUCCESS
        }
        Cmd::Analyze { command, mode } => {
            let env = Env::from_process();
            let loaded = config::load(
                &env,
                &CliOverrides {
                    mode: mode.map(Mode::from),
                    ..CliOverrides::default()
                },
            );
            let opts = Options {
                mode: loaded.config.mode,
                home: env.home.unwrap_or_default(),
                care: loaded.config.tunables.care,
                ..Options::default()
            };
            match engine::analyze(&command, &opts) {
                Ok(a) => match serde_json::to_string_pretty(&a) {
                    Ok(s) => {
                        println!("{s}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("cancelli: {e}");
                        ExitCode::FAILURE
                    }
                },
                Err(e) => {
                    eprintln!("cancelli: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Judge {
            command,
            transcript,
            request,
            decide_all,
        } => {
            let env = Env::from_process();
            let rec = hook::judge_cli(&command, transcript, request, decide_all, &env);
            match serde_json::to_string_pretty(&rec) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("cancelli: {e}");
                    return ExitCode::FAILURE;
                }
            }
            if rec.error.is_some() {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Cmd::Config { init } => {
            let env = Env::from_process();
            if init {
                match config::init(&env) {
                    Ok(p) => {
                        println!("wrote {}", p.display());
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("cancelli: {e}");
                        ExitCode::FAILURE
                    }
                }
            } else {
                print!(
                    "{}",
                    config::render(&config::load(&env, &CliOverrides::default()), &env)
                );
                ExitCode::SUCCESS
            }
        }
    }
}
