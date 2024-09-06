#[derive(thiserror::Error, Debug)]
pub enum AptosContainerError {
    /// Represents an IO error, wrapping a standard `std::io::Error`.
    #[error("io error {0}")]
    IOError(#[from] std::io::Error),

    /// Indicates that the file size is too large, providing the file path and its size in MB.
    #[error("file {path}:{size}MB is too big (max: 1MB)")]
    FileSizeTooBig { path: String, size: f64 },

    /// Represents an error where a Docker exec command failed, providing the returned code.
    #[error("docker exec failed with returned code: {0}")]
    DockerExecFailed(i64),

    /// Indicates that a command failed to execute, providing the command and the associated stderr output.
    #[error("run command {command} failed: {stderr}")]
    CommandFailed { command: String, stderr: String },
}
