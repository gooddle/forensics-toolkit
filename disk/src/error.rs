use thiserror::Error;

#[derive(Debug, Error)]
pub enum DiskError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("MBR 시그니처 불일치: 0x{0:04X}")]
    InvalidMbrSignature(u16),

    #[error("GPT 헤더 파싱 실패: {0}")]
    GptParseFailed(String),

    #[error("지원하지 않는 파일시스템: {0}")]
    UnsupportedFilesystem(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
