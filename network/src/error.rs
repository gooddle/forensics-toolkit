use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("유효하지 않은 PCAP 시그니처: 0x{0:08X}")]
    InvalidPcapSignature(u32),

    #[error("지원하지 않는 링크 타입: {0}")]
    UnsupportedLinkType(u32),

    #[error("PCAP 파싱 실패: {0}")]
    ParseFailed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
