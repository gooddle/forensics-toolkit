use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("유효하지 않은 Minidump 시그니처: 0x{0:08X}")]
    InvalidMinidumpSignature(u32),

    #[error("지원하지 않는 메모리 덤프 포맷: {0}")]
    UnsupportedFormat(String),

    #[error("유효하지 않은 regex 패턴: {0}")]
    InvalidPattern(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
