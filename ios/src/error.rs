use thiserror::Error;

#[derive(Debug, Error)]
pub enum IosError {
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

    #[error("지원하지 않는 형식: {0}")]
    UnsupportedFormat(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<common::sqlite::SqliteError> for IosError {
    fn from(e: common::sqlite::SqliteError) -> Self {
        use common::sqlite::SqliteError as E;
        match e {
            E::OpenFailed { path, source } => IosError::OpenFailed { path, source },
            E::NonUtf8Path(p) => {
                IosError::UnsupportedFormat(format!("UTF-8 이 아닌 경로는 지원하지 않음: {p}"))
            }
            E::Sqlite(m) => IosError::SqliteError(m),
            E::SchemaMismatch(m) => IosError::SchemaMismatch(m),
        }
    }
}
