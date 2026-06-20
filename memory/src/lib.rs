pub mod error;
pub mod info;
pub mod minidump;
pub mod scan;
pub mod strings;

pub use error::MemoryError;
pub use info::{analyze_memory_image, MemoryImageInfo};
pub use minidump::{parse_minidump, MinidumpInfo, StreamEntry};
pub use scan::{scan_pattern, ScanMatch};
pub use strings::{extract_strings, StringEntry};
