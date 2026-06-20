use crate::error::WindowsError;
use evtx::EvtxParser;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct EventRecord {
    pub record_id: u64,
    pub timestamp: String,
    pub event_id: u64,
    pub level: String,
    pub channel: String,
    pub computer: String,
    pub message: String,
}

fn level_name(n: u64) -> &'static str {
    match n {
        0 => "LogAlways",
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        _ => "Unknown",
    }
}

fn extract_str(v: &Value, pointer: &str) -> String {
    v.pointer(pointer)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn extract_u64(v: &Value, pointer: &str) -> u64 {
    v.pointer(pointer)
        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))
        .unwrap_or(0)
}

pub fn parse_evtx(path: &Path, limit: usize) -> Result<Vec<EventRecord>, WindowsError> {
    let mut parser = EvtxParser::from_path(path)
        .map_err(|e| WindowsError::EvtxParseFailed(e.to_string()))?;

    let mut records = Vec::new();

    for rec in parser
        .records_json_value()
        .take(if limit == 0 { usize::MAX } else { limit })
    {
        let rec = match rec {
            Ok(r) => r,
            Err(_) => continue,
        };

        let data = &rec.data;

        let event_id = extract_u64(data, "/Event/System/EventID");
        let level_num = extract_u64(data, "/Event/System/Level");
        let channel = extract_str(data, "/Event/System/Channel");
        let computer = extract_str(data, "/Event/System/Computer");

        // Collect EventData fields into a short summary
        let message = if let Some(ed) = data.pointer("/Event/EventData") {
            match ed {
                Value::Object(map) => map
                    .iter()
                    .filter_map(|(k, v)| {
                        v.as_str().map(|s| format!("{k}={s}"))
                    })
                    .take(5)
                    .collect::<Vec<_>>()
                    .join("; "),
                Value::String(s) => s.clone(),
                _ => String::new(),
            }
        } else {
            String::new()
        };

        records.push(EventRecord {
            record_id: rec.event_record_id,
            timestamp: rec.timestamp.to_rfc3339(),
            event_id,
            level: level_name(level_num).to_string(),
            channel,
            computer,
            message,
        });
    }

    Ok(records)
}
