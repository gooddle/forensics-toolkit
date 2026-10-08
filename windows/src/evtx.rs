use crate::error::WindowsError;
use evtx::{EvtxParser, SerializedEvtxRecord};
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

/// Result of an EVTX scan: matched records plus the number of records that
/// failed to parse and were skipped.
#[derive(Debug)]
pub struct EvtxScan {
    pub records: Vec<EventRecord>,
    pub skipped: usize,
}

/// Parses an EVTX file. `event_id` is applied while parsing, and `limit`
/// (0 = unlimited) caps the number of *matching* records.
pub fn parse_evtx(
    path: &Path,
    limit: usize,
    event_id: Option<u64>,
) -> Result<EvtxScan, WindowsError> {
    let mut parser =
        EvtxParser::from_path(path).map_err(|e| WindowsError::EvtxParseFailed(e.to_string()))?;

    Ok(collect_records(
        parser.records_json_value(),
        limit,
        event_id,
    ))
}

fn collect_records<I, E>(iter: I, limit: usize, event_id: Option<u64>) -> EvtxScan
where
    I: Iterator<Item = Result<SerializedEvtxRecord<Value>, E>>,
{
    let limit = if limit == 0 { usize::MAX } else { limit };
    let mut records = Vec::new();
    let mut skipped = 0usize;

    for rec in iter {
        if records.len() >= limit {
            break;
        }

        let rec = match rec {
            Ok(r) => r,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        let data = &rec.data;

        let eid = extract_u64(data, "/Event/System/EventID");
        if event_id.is_some_and(|wanted| wanted != eid) {
            continue;
        }

        let level_num = extract_u64(data, "/Event/System/Level");
        let channel = extract_str(data, "/Event/System/Channel");
        let computer = extract_str(data, "/Event/System/Computer");

        // Collect EventData fields into a short summary
        let message = if let Some(ed) = data.pointer("/Event/EventData") {
            match ed {
                Value::Object(map) => map
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| format!("{k}={s}")))
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
            event_id: eid,
            level: level_name(level_num).to_string(),
            channel,
            computer,
            message,
        });
    }

    EvtxScan { records, skipped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn rec(id: u64, event_id: u64) -> Result<SerializedEvtxRecord<Value>, String> {
        Ok(SerializedEvtxRecord {
            event_record_id: id,
            timestamp: Utc.timestamp_opt(1_704_067_200, 0).unwrap(),
            data: json!({
                "Event": {
                    "System": {
                        "EventID": event_id,
                        "Level": 4,
                        "Channel": "Security",
                        "Computer": "HOST"
                    },
                    "EventData": { "TargetUserName": "alice" }
                }
            }),
        })
    }

    #[test]
    fn test_event_id_filter_applied_before_limit() {
        // Matching 4624 records sit beyond the first `limit` records.
        let input = vec![
            rec(1, 4688),
            rec(2, 4688),
            rec(3, 4688),
            rec(4, 4624),
            rec(5, 4624),
            rec(6, 4624),
        ];
        let scan = collect_records(input.into_iter(), 2, Some(4624));
        let ids: Vec<u64> = scan.records.iter().map(|r| r.record_id).collect();
        assert_eq!(ids, vec![4, 5]);
        assert!(scan.records.iter().all(|r| r.event_id == 4624));
        assert_eq!(scan.skipped, 0);
    }

    #[test]
    fn test_limit_zero_is_unlimited_and_no_filter_keeps_all() {
        let input = vec![rec(1, 1), rec(2, 2), rec(3, 3)];
        let scan = collect_records(input.into_iter(), 0, None);
        assert_eq!(scan.records.len(), 3);
        assert_eq!(scan.records[0].message, "TargetUserName=alice");
    }

    #[test]
    fn test_failed_records_are_counted_as_skipped() {
        let input = vec![
            rec(1, 4624),
            Err("corrupt chunk".to_string()),
            rec(2, 4624),
            Err("bad xml".to_string()),
        ];
        let scan = collect_records(input.into_iter(), 0, None);
        assert_eq!(scan.records.len(), 2);
        assert_eq!(scan.skipped, 2);
    }
}
