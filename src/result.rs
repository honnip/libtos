use thiserror::Error as ThisError;

pub type IpfResult<T> = Result<T, IpfError>;

/// Error type for Ipf
#[derive(Debug, ThisError)]
pub enum IpfError {
    /// An error caused by I/O
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The ipf archive contained invalid data per the spec.
    #[error("Invalid ipf archive: {0}")]
    InvalidArchive(&'static str),

    /// The requested file could not be found in the archive
    #[error("Specified file not found in archive")]
    FileNotFound,

    /// Decoding a UTF-8 string failed
    #[error("Invalid UTF-8")]
    Encoding(#[from] std::string::FromUtf8Error),
}

impl From<IpfError> for std::io::Error {
    fn from(err: IpfError) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, err)
    }
}
