use chrono::{DateTime, TimeZone, Utc};

pub fn format_unix_ts(secs: i64) -> String {
    match Utc.timestamp_opt(secs, 0) {
        chrono::LocalResult::Single(dt) => dt.to_rfc3339(),
        _ => "invalid timestamp".to_string(),
    }
}

pub fn fat_datetime(date: u16, time: u16) -> String {
    let year = 1980 + ((date >> 9) & 0x7F) as i32;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    let minute = ((time >> 5) & 0x3F) as u32;
    let second = ((time & 0x1F) * 2) as u32;

    if let Some(dt) = chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, minute, second))
    {
        DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()
    } else {
        "invalid fat timestamp".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_unix_ts_epoch() {
        assert_eq!(format_unix_ts(0), "1970-01-01T00:00:00+00:00");
    }
}
