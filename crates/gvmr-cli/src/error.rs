use std::{fmt, io};

#[derive(Debug)]
pub enum CliError {
    Validation(String),
    Io {
        action: &'static str,
        path: String,
        source: io::Error,
    },
    Xml(String),
    Render {
        renderer: &'static str,
        message: String,
    },
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(message) => write!(formatter, "{message}"),

            Self::Io {
                action,
                path,
                source,
            } => {
                write!(formatter, "failed to {action} {path}: {source}")
            }

            Self::Xml(message) => write!(formatter, "{message}"),

            Self::Render { renderer, message } => {
                write!(formatter, "{renderer} render failed: {message}")
            }
        }
    }
}

impl std::error::Error for CliError {}
