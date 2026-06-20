use thiserror::Error;

#[derive(Debug, Error)]
pub enum WindowsError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("유효하지 않은 Prefetch 시그니처")]
    InvalidPrefetchSignature,

    #[error("지원하지 않는 Prefetch 버전: {0}")]
    UnsupportedPrefetchVersion(u32),

    #[error("EVTX 파싱 실패: {0}")]
    EvtxParseFailed(String),

    #[error("레지스트리 하이브 파싱 실패: {0}")]
    HiveParseFailed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
