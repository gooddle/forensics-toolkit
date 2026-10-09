use crate::error::AndroidError;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use serde::Serialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct PackageInfo {
    pub name: String,
    pub code_path: String,
    pub is_system: bool,
    pub first_install: i64,
    pub last_update: i64,
}

/// packages.xml 입력 크기 상한 (실제 파일은 수 MB 수준)
const MAX_PACKAGES_XML_SIZE: u64 = 256 * 1024 * 1024;

/// Android 12+ 바이너리 XML(ABX) 매직
const ABX_MAGIC: &[u8; 4] = b"ABX\0";

/// 시스템 파티션 경로 접두사
const SYSTEM_PREFIXES: &[&str] = &[
    "/system/",
    "/product/",
    "/vendor/",
    "/system_ext/",
    "/apex/",
];

/// `/data/system/packages.xml` 파싱 (텍스트 XML / ABX 자동 감지)
pub fn parse_packages(xml_path: &Path) -> Result<Vec<PackageInfo>, AndroidError> {
    let open_err = |source| AndroidError::OpenFailed {
        path: xml_path.display().to_string(),
        source,
    };
    let meta = fs::metadata(xml_path).map_err(open_err)?;
    if meta.len() > MAX_PACKAGES_XML_SIZE {
        return Err(AndroidError::UnsupportedFormat(format!(
            "packages.xml 크기 초과: {} bytes (상한 {MAX_PACKAGES_XML_SIZE})",
            meta.len()
        )));
    }
    let data = fs::read(xml_path).map_err(open_err)?;
    let (packages, skipped) = parse_packages_bytes(&data)?;
    if skipped > 0 {
        eprintln!("경고: packages.xml 에서 파싱 실패한 package 항목 {skipped}건 건너뜀");
    }
    Ok(packages)
}

/// 바이트 버퍼에서 package 목록 파싱. (결과, 건너뛴 항목 수) 반환.
pub fn parse_packages_bytes(data: &[u8]) -> Result<(Vec<PackageInfo>, usize), AndroidError> {
    let mut collector = Collector::default();
    if data.starts_with(ABX_MAGIC) {
        parse_abx(data, &mut collector)?;
    } else {
        parse_text_xml(data, &mut collector)?;
    }
    if !collector.saw_root {
        return Err(AndroidError::SchemaMismatch(
            "루트 <packages> 요소가 없음".into(),
        ));
    }
    Ok((collector.packages, collector.skipped))
}

pub fn is_system_path(code_path: &str) -> bool {
    SYSTEM_PREFIXES.iter().any(|p| code_path.starts_with(p))
}

/// package 태그에서 수집한 원시 속성
#[derive(Default)]
struct RawPackage {
    name: Option<String>,
    code_path: Option<String>,
    first_install_ms: Option<i64>,
    last_update_ms: Option<i64>,
    /// 속성 값 해석 실패 (잘못된 16진수 등)
    invalid: bool,
}

impl RawPackage {
    /// 속성 하나 반영. AOSP 실제 이름(`it`/`ut`)과 설계 문서 이름
    /// (`firstInstallTime`/`lastUpdateTime`) 모두 지원.
    fn set(&mut self, key: &str, value: AttrValue) {
        match key {
            "name" => self.name = value.into_string(),
            "codePath" => self.code_path = value.into_string(),
            "it" | "firstInstallTime" => match value.as_millis() {
                Some(v) => self.first_install_ms = Some(v),
                None => self.invalid = true,
            },
            "ut" | "lastUpdateTime" => match value.as_millis() {
                Some(v) => self.last_update_ms = Some(v),
                None => self.invalid = true,
            },
            _ => {}
        }
    }

    fn finish(self) -> Option<PackageInfo> {
        if self.invalid {
            return None;
        }
        let name = self.name.filter(|n| !n.is_empty())?;
        let code_path = self.code_path?;
        Some(PackageInfo {
            is_system: is_system_path(&code_path),
            name,
            code_path,
            // 시각 속성이 없으면 0 (알 수 없음)
            first_install: self.first_install_ms.unwrap_or(0) / 1000,
            last_update: self.last_update_ms.unwrap_or(0) / 1000,
        })
    }
}

enum AttrValue {
    Str(String),
    Int(i64),
    Other,
}

impl AttrValue {
    fn into_string(self) -> Option<String> {
        match self {
            AttrValue::Str(s) => Some(s),
            AttrValue::Int(v) => Some(v.to_string()),
            AttrValue::Other => None,
        }
    }

    /// 16진수 ms 문자열 또는 정수(ABX long/long-hex) → ms
    fn as_millis(&self) -> Option<i64> {
        match self {
            AttrValue::Str(s) => parse_hex_ms(s),
            AttrValue::Int(v) => Some(*v),
            AttrValue::Other => None,
        }
    }
}

fn parse_hex_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    // 음수 ms 는 Java Long.toHexString 이 2의 보수로 기록하므로 u64 로 받아 변환
    u64::from_str_radix(s, 16).ok().map(|v| v as i64)
}

fn is_package_tag(name: &str) -> bool {
    name == "package" || name == "updated-package"
}

#[derive(Default)]
struct Collector {
    packages: Vec<PackageInfo>,
    skipped: usize,
    saw_root: bool,
}

impl Collector {
    fn push(&mut self, raw: RawPackage) {
        match raw.finish() {
            Some(p) => self.packages.push(p),
            None => self.skipped += 1,
        }
    }
}

// ---------------------------------------------------------------------------
// 텍스트 XML
// ---------------------------------------------------------------------------

fn parse_text_xml(data: &[u8], out: &mut Collector) -> Result<(), AndroidError> {
    let mut reader = Reader::from_reader(data);
    let mut buf = Vec::new();
    let mut depth: usize = 0;
    loop {
        let event = reader.read_event_into(&mut buf).map_err(|e| {
            AndroidError::XmlParseFailed(format!("위치 {}: {e}", reader.error_position()))
        })?;
        match event {
            Event::Start(ref e) => {
                handle_text_element(e, depth, out);
                depth += 1;
            }
            Event::Empty(ref e) => handle_text_element(e, depth, out),
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => {
                if depth != 0 {
                    return Err(AndroidError::XmlParseFailed(
                        "닫히지 않은 요소가 남은 채 파일이 끝남 (잘린 파일)".into(),
                    ));
                }
                break;
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(())
}

fn handle_text_element(e: &BytesStart, depth: usize, out: &mut Collector) {
    let name = e.name();
    let name = String::from_utf8_lossy(name.as_ref());
    if depth == 0 {
        if name == "packages" {
            out.saw_root = true;
        }
        return;
    }
    // package 항목은 루트 바로 아래(depth 1)에만 존재
    if depth != 1 || !is_package_tag(&name) {
        return;
    }
    let mut raw = RawPackage::default();
    for attr in e.attributes() {
        let Ok(attr) = attr else {
            raw.invalid = true;
            continue;
        };
        let key = String::from_utf8_lossy(attr.key.as_ref()).into_owned();
        match attr.unescape_value() {
            Ok(v) => raw.set(&key, AttrValue::Str(v.into_owned())),
            Err(_) => raw.invalid = true,
        }
    }
    out.push(raw);
}

// ---------------------------------------------------------------------------
// ABX (AOSP BinaryXmlSerializer)
// ---------------------------------------------------------------------------

const TOKEN_START_DOCUMENT: u8 = 0;
const TOKEN_END_DOCUMENT: u8 = 1;
const TOKEN_START_TAG: u8 = 2;
const TOKEN_END_TAG: u8 = 3;
const TOKEN_TEXT: u8 = 4;
const TOKEN_CDSECT: u8 = 5;
const TOKEN_ENTITY_REF: u8 = 6;
const TOKEN_IGNORABLE_WHITESPACE: u8 = 7;
const TOKEN_PROCESSING_INSTRUCTION: u8 = 8;
const TOKEN_COMMENT: u8 = 9;
const TOKEN_DOCDECL: u8 = 10;
const TOKEN_ATTRIBUTE: u8 = 15;

const TYPE_NULL: u8 = 1;
const TYPE_STRING: u8 = 2;
const TYPE_STRING_INTERNED: u8 = 3;
const TYPE_BYTES_HEX: u8 = 4;
const TYPE_BYTES_BASE64: u8 = 5;
const TYPE_INT: u8 = 6;
const TYPE_INT_HEX: u8 = 7;
const TYPE_LONG: u8 = 8;
const TYPE_LONG_HEX: u8 = 9;
const TYPE_FLOAT: u8 = 10;
const TYPE_DOUBLE: u8 = 11;
const TYPE_BOOLEAN_TRUE: u8 = 12;
const TYPE_BOOLEAN_FALSE: u8 = 13;

/// 인터닝 테이블에 새 문자열이 뒤따름을 나타내는 인덱스
const INTERNED_NEW: u16 = 0xFFFF;

struct AbxReader<'a> {
    data: &'a [u8],
    pos: usize,
    interned: Vec<String>,
}

impl<'a> AbxReader<'a> {
    fn truncated(&self) -> AndroidError {
        AndroidError::XmlParseFailed(format!("ABX: 오프셋 {} 에서 데이터 잘림", self.pos))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AndroidError> {
        let end = self.pos.checked_add(n).ok_or_else(|| self.truncated())?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| self.truncated())?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, AndroidError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AndroidError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn i32(&mut self) -> Result<i32, AndroidError> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn i64(&mut self) -> Result<i64, AndroidError> {
        let b = self.take(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(i64::from_be_bytes(arr))
    }

    /// Java DataOutput.writeUTF 형식: u16 BE 바이트 길이 + modified UTF-8
    fn utf(&mut self) -> Result<String, AndroidError> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        Ok(decode_modified_utf8(bytes))
    }

    fn interned(&mut self) -> Result<String, AndroidError> {
        let idx = self.u16()?;
        if idx == INTERNED_NEW {
            let s = self.utf()?;
            self.interned.push(s.clone());
            return Ok(s);
        }
        self.interned.get(idx as usize).cloned().ok_or_else(|| {
            AndroidError::XmlParseFailed(format!(
                "ABX: 오프셋 {} 의 인터닝 문자열 인덱스 {idx} 범위 밖",
                self.pos
            ))
        })
    }

    /// 데이터 타입에 따른 값 읽기
    fn value(&mut self, ty: u8) -> Result<AttrValue, AndroidError> {
        Ok(match ty {
            TYPE_NULL | TYPE_BOOLEAN_TRUE | TYPE_BOOLEAN_FALSE => AttrValue::Other,
            TYPE_STRING => AttrValue::Str(self.utf()?),
            TYPE_STRING_INTERNED => AttrValue::Str(self.interned()?),
            TYPE_BYTES_HEX | TYPE_BYTES_BASE64 => {
                let len = self.u16()? as usize;
                self.take(len)?;
                AttrValue::Other
            }
            TYPE_INT | TYPE_INT_HEX => AttrValue::Int(i64::from(self.i32()?)),
            TYPE_LONG | TYPE_LONG_HEX => AttrValue::Int(self.i64()?),
            TYPE_FLOAT => {
                self.take(4)?;
                AttrValue::Other
            }
            TYPE_DOUBLE => {
                self.take(8)?;
                AttrValue::Other
            }
            other => {
                return Err(AndroidError::UnsupportedFormat(format!(
                    "ABX: 오프셋 {} 의 알 수 없는 데이터 타입 {other}",
                    self.pos.saturating_sub(1)
                )));
            }
        })
    }
}

fn parse_abx(data: &[u8], out: &mut Collector) -> Result<(), AndroidError> {
    let mut r = AbxReader {
        data,
        pos: ABX_MAGIC.len(),
        interned: Vec::new(),
    };
    let mut depth: usize = 0;
    // 현재 열려 있는(속성 수집 중인) package 태그
    let mut current: Option<RawPackage> = None;
    let mut ended = false;

    while r.pos < data.len() {
        let byte = r.u8()?;
        let token = byte & 0x0F;
        let ty = byte >> 4;

        if token == TOKEN_ATTRIBUTE {
            let key = r.interned()?;
            let value = r.value(ty)?;
            if let Some(raw) = current.as_mut() {
                raw.set(&key, value);
            }
            continue;
        }
        // 속성이 아닌 토큰이 나오면 직전 시작 태그의 속성 수집 종료
        if let Some(raw) = current.take() {
            out.push(raw);
        }

        match token {
            TOKEN_START_TAG => {
                let name = match ty {
                    TYPE_STRING_INTERNED => r.interned()?,
                    TYPE_STRING => r.utf()?,
                    _ => return Err(abx_bad_type(&r, token, ty)),
                };
                if depth == 0 {
                    if name == "packages" {
                        out.saw_root = true;
                    }
                } else if depth == 1 && is_package_tag(&name) {
                    current = Some(RawPackage::default());
                }
                depth += 1;
            }
            TOKEN_END_TAG => {
                match ty {
                    TYPE_STRING_INTERNED => {
                        r.interned()?;
                    }
                    TYPE_STRING => {
                        r.utf()?;
                    }
                    _ => return Err(abx_bad_type(&r, token, ty)),
                }
                depth = depth.saturating_sub(1);
            }
            TOKEN_START_DOCUMENT => {}
            TOKEN_END_DOCUMENT => {
                ended = true;
                break;
            }
            TOKEN_TEXT
            | TOKEN_CDSECT
            | TOKEN_ENTITY_REF
            | TOKEN_IGNORABLE_WHITESPACE
            | TOKEN_PROCESSING_INSTRUCTION
            | TOKEN_COMMENT
            | TOKEN_DOCDECL => match ty {
                TYPE_NULL => {}
                TYPE_STRING => {
                    r.utf()?;
                }
                TYPE_STRING_INTERNED => {
                    r.interned()?;
                }
                _ => return Err(abx_bad_type(&r, token, ty)),
            },
            _ => {
                return Err(AndroidError::UnsupportedFormat(format!(
                    "ABX: 오프셋 {} 의 알 수 없는 토큰 {token}",
                    r.pos.saturating_sub(1)
                )));
            }
        }
    }
    if let Some(raw) = current.take() {
        out.push(raw);
    }
    if !ended || depth != 0 {
        return Err(AndroidError::XmlParseFailed(format!(
            "ABX: END_DOCUMENT 전에 데이터가 끝남 (잘린 파일, 열린 요소 {depth}개)"
        )));
    }
    Ok(())
}

fn abx_bad_type(r: &AbxReader, token: u8, ty: u8) -> AndroidError {
    AndroidError::UnsupportedFormat(format!(
        "ABX: 오프셋 {} 의 토큰 {token} 에 지원하지 않는 데이터 타입 {ty}",
        r.pos.saturating_sub(1)
    ))
}

/// Java modified UTF-8 (CESU-8 서로게이트, `C0 80` NUL) 디코딩. 잘못된 바이트는 U+FFFD.
fn decode_modified_utf8(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let cont = |j: usize| bytes.get(j).copied().filter(|b| b & 0xC0 == 0x80);
        if b0 < 0x80 {
            units.push(u16::from(b0));
            i += 1;
        } else if b0 & 0xE0 == 0xC0 {
            match cont(i + 1) {
                Some(b1) => {
                    units.push((u16::from(b0 & 0x1F) << 6) | u16::from(b1 & 0x3F));
                    i += 2;
                }
                None => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else if b0 & 0xF0 == 0xE0 {
            match (cont(i + 1), cont(i + 2)) {
                (Some(b1), Some(b2)) => {
                    units.push(
                        (u16::from(b0 & 0x0F) << 12)
                            | (u16::from(b1 & 0x3F) << 6)
                            | u16::from(b2 & 0x3F),
                    );
                    i += 3;
                }
                _ => {
                    units.push(0xFFFD);
                    i += 1;
                }
            }
        } else {
            units.push(0xFFFD);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ms_parsing() {
        assert_eq!(parse_hex_ms("17c4f3a2b10"), Some(0x17c4f3a2b10));
        assert_eq!(parse_hex_ms("0x10"), Some(16));
        assert_eq!(parse_hex_ms(""), None);
        assert_eq!(parse_hex_ms("zz"), None);
    }

    #[test]
    fn system_path_detection() {
        assert!(is_system_path("/system/app/Foo"));
        assert!(is_system_path("/apex/com.android.foo"));
        assert!(is_system_path("/system_ext/priv-app/Bar"));
        assert!(!is_system_path("/data/app/com.evil-1"));
        assert!(!is_system_path("/systemfoo/app"));
    }

    #[test]
    fn modified_utf8_decoding() {
        // C0 80 = NUL, ED A0 BD ED B8 80 = U+1F600 (CESU-8)
        let bytes = [b'a', 0xC0, 0x80, 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        assert_eq!(decode_modified_utf8(&bytes), "a\0\u{1F600}");
        assert_eq!(decode_modified_utf8(&[0xFF, b'b']), "\u{FFFD}b");
    }
}
