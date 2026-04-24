use std::{collections::HashMap, io, path::Path, process::Stdio, time::Duration};

use tokio::{process::Command, time};
use tracing::{debug, warn};

#[derive(Debug)]
pub struct CommandOutput {
    pub returncode: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub async fn run_cmd(
    args: &[String],
    cwd: &Path,
    envs: Option<&HashMap<String, String>>,
    timeout_seconds: u64,
) -> io::Result<CommandOutput> {
    if args.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "command args must not be empty",
        ));
    }

    debug!(
        command = %args.join(" "),
        cwd = %cwd.display(),
        timeout_seconds,
        "running command"
    );

    let mut command = Command::new(&args[0]);

    command
        .args(&args[1..])
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    if let Some(envs) = envs {
        command.envs(envs);
    }

    let child = command.spawn()?;

    let output = match time::timeout(
        Duration::from_secs(timeout_seconds),
        child.wait_with_output(),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            warn!(
                command = %args.join(" "),
                cwd = %cwd.display(),
                timeout_seconds,
                "command timed out"
            );

            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "command timed out after {timeout_seconds}s: {}",
                    args.join(" ")
                ),
            ));
        }
    };

    let returncode = output.status.code().unwrap_or(-1);
    let stdout = output.stdout;
    let stderr = output.stderr;

    debug!(
        command = %args.join(" "),
        returncode,
        stdout_len = stdout.len(),
        stderr_len = stderr.len(),
        "command finished"
    );

    Ok(CommandOutput {
        returncode,
        stdout,
        stderr,
    })
}
