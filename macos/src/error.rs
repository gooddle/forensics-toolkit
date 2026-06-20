use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacosError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Plist 파싱 실패: {0}")]
    PlistParseFailed(String),

    #[error("SQLite 오류: {0}")]
    SqliteError(String),

    #[error("경로를 찾을 수 없음: {0}")]
    PathNotFound(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
