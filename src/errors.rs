#[derive(thiserror::Error, Debug)]
pub enum AptosContainerError {
    #[error("io error {0}")]
    IOError(#[from] std::io::Error),

    #[error("file {path}:{size}MB is too big (max: 1MB)")]
    FileSizeTooBig{
        path: String,
        size: f64
    },

    #[error("docker exec failed with returned code: {0}")]
    DockerExecFailed(i64),

    #[error("run command {command} failed: {stderr}")]
    CommandFailed {
        command: String,
        stderr: String,
    },
}