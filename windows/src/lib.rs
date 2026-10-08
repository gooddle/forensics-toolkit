pub mod error;
pub mod evtx;
pub mod prefetch;
pub mod registry;

pub use error::WindowsError;
pub use evtx::{EventRecord, EvtxScan, parse_evtx};
pub use prefetch::{parse_prefetch, PrefetchInfo};
pub use registry::{extract_run_keys, RunEntry};
