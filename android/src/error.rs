use thiserror::Error;

#[derive(Debug, Error)]
pub enum AndroidError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("SQLite 오류: {0}")]
    SqliteError(String),

    #[error("스키마 불일치: {0}")]
    SchemaMismatch(String),

    #[error("XML 파싱 실패: {0}")]
    XmlParseFailed(String),

    #[error("지원하지 않는 형식: {0}")]
    UnsupportedFormat(String),

    #[error("ZIP 오류: {0}")]
    ZipError(String),

    #[error("AXML 파싱 실패: {0}")]
    AxmlParseFailed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<common::sqlite::SqliteError> for AndroidError {
    fn from(e: common::sqlite::SqliteError) -> Self {
        use common::sqlite::SqliteError as E;
        match e {
            E::OpenFailed { path, source } => AndroidError::OpenFailed { path, source },
            E::NonUtf8Path(p) => {
                AndroidError::UnsupportedFormat(format!("UTF-8 이 아닌 경로는 지원하지 않음: {p}"))
            }
            E::Sqlite(m) => AndroidError::SqliteError(m),
            E::SchemaMismatch(m) => AndroidError::SchemaMismatch(m),
        }
    }
}
