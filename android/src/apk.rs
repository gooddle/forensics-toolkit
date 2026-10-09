use crate::error::AndroidError;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ApkPermissions {
    pub package_name: String,
    pub all_permissions: Vec<String>,
    pub dangerous_permissions: Vec<String>,
}

/// 위험(민감) 권한 목록 — 설계 문서 목록 + 최신 Android 위험/특수 권한
pub const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_BIOMETRIC",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.BODY_SENSORS",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
];

/// AndroidManifest.xml 압축 해제 크기 상한
pub const MAX_MANIFEST_SIZE: u64 = 16 * 1024 * 1024;

const MANIFEST_ENTRY: &str = "AndroidManifest.xml";

/// AXML 파일 매직 (RES_XML_TYPE=0x0003, headerSize=8)
const AXML_MAGIC: u32 = 0x0008_0003;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;

const STRING_POOL_UTF8_FLAG: u32 = 0x100;
/// Res_value.dataType: 문자열 풀 인덱스
const TYPE_STRING: u8 = 0x03;
/// rawValue 없음
const NO_INDEX: u32 = 0xFFFF_FFFF;
/// android:name 속성 리소스 ID (난독화로 속성명 문자열이 지워진 경우 대비)
const ATTR_ANDROID_NAME: u32 = 0x0101_0003;

const CHUNK_HEADER_SIZE: usize = 8;
const ATTRIBUTE_MIN_SIZE: usize = 20;

/// APK 를 열어 AndroidManifest.xml 의 패키지명·권한 분석
pub fn analyze_apk(apk_path: &Path) -> Result<ApkPermissions, AndroidError> {
    let file = File::open(apk_path).map_err(|source| AndroidError::OpenFailed {
        path: apk_path.display().to_string(),
        source,
    })?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| AndroidError::ZipError(e.to_string()))?;
    let entry = archive.by_name(MANIFEST_ENTRY).map_err(|e| {
        AndroidError::ZipError(format!("{MANIFEST_ENTRY} 항목을 읽을 수 없음: {e}"))
    })?;

    let mut manifest = Vec::new();
    entry
        .take(MAX_MANIFEST_SIZE + 1)
        .read_to_end(&mut manifest)
        .map_err(|e| AndroidError::ZipError(format!("{MANIFEST_ENTRY} 압축 해제 실패: {e}")))?;
    if manifest.len() as u64 > MAX_MANIFEST_SIZE {
        return Err(AndroidError::UnsupportedFormat(format!(
            "{MANIFEST_ENTRY} 압축 해제 크기가 상한({MAX_MANIFEST_SIZE} bytes) 초과"
        )));
    }

    let (result, skipped) = parse_manifest(&manifest)?;
    if skipped > 0 {
        eprintln!("경고: AndroidManifest.xml 에서 해석 실패한 요소/속성 {skipped}건 건너뜀");
    }
    Ok(result)
}

/// 바이너리 AXML 매니페스트 파싱. (결과, 건너뛴 요소/속성 수) 반환.
pub fn parse_manifest(data: &[u8]) -> Result<(ApkPermissions, usize), AndroidError> {
    let magic = read_u32(data, 0).ok_or_else(|| axml_err("파일 헤더가 잘림"))?;
    if magic != AXML_MAGIC {
        return Err(AndroidError::AxmlParseFailed(format!(
            "잘못된 AXML 매직: 0x{magic:08x}"
        )));
    }
    let header_size = read_u16(data, 2)
        .map(usize::from)
        .unwrap_or(CHUNK_HEADER_SIZE);
    // 파일 헤더의 전체 크기 필드는 조작되는 경우가 많아 실제 버퍼 길이와 비교해 작은 쪽 사용
    let total = read_u32(data, 4)
        .map(|s| (s as usize).min(data.len()))
        .unwrap_or(data.len());
    let total = if total < header_size {
        data.len()
    } else {
        total
    };

    let mut pool: Option<StringPool> = None;
    let mut res_map: &[u8] = &[];
    let mut package_name: Option<String> = None;
    let mut saw_manifest = false;
    let mut permissions: Vec<String> = Vec::new();
    let mut skipped = 0usize;

    let mut pos = header_size.max(CHUNK_HEADER_SIZE);
    while pos + CHUNK_HEADER_SIZE <= total {
        let (Some(ty), Some(chunk_header), Some(chunk_size)) = (
            read_u16(data, pos),
            read_u16(data, pos + 2),
            read_u32(data, pos + 4),
        ) else {
            break;
        };
        let chunk_size = chunk_size as usize;
        let chunk_header = usize::from(chunk_header);
        if chunk_size < CHUNK_HEADER_SIZE || chunk_header < CHUNK_HEADER_SIZE {
            return Err(AndroidError::AxmlParseFailed(format!(
                "오프셋 {pos} 의 청크 크기가 비정상 (size={chunk_size}, header={chunk_header})"
            )));
        }
        let end = pos
            .checked_add(chunk_size)
            .filter(|&e| e <= total)
            .ok_or_else(|| {
                AndroidError::AxmlParseFailed(format!(
                    "오프셋 {pos} 의 청크(크기 {chunk_size})가 파일 범위를 벗어남"
                ))
            })?;
        let chunk = &data[pos..end];

        match ty {
            RES_STRING_POOL_TYPE if pool.is_none() => {
                pool = Some(StringPool::new(chunk, chunk_header)?);
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                res_map = chunk.get(chunk_header..).unwrap_or(&[]);
            }
            RES_XML_START_ELEMENT_TYPE => {
                let strings = pool
                    .as_ref()
                    .ok_or_else(|| axml_err("문자열 풀보다 START_ELEMENT 가 먼저 나옴"))?;
                match parse_start_element(chunk, chunk_header) {
                    Some(elem) => handle_element(
                        &elem,
                        strings,
                        res_map,
                        &mut ElementSink {
                            package_name: &mut package_name,
                            saw_manifest: &mut saw_manifest,
                            permissions: &mut permissions,
                            skipped: &mut skipped,
                        },
                    ),
                    None => skipped += 1,
                }
            }
            _ => {}
        }
        pos = end;
    }

    if pool.is_none() {
        return Err(axml_err("문자열 풀 청크가 없음"));
    }
    if !saw_manifest {
        return Err(axml_err("<manifest> 요소가 없음"));
    }
    let package_name =
        package_name.ok_or_else(|| axml_err("<manifest> 의 package 속성을 해석할 수 없음"))?;

    let dangerous_permissions = permissions
        .iter()
        .filter(|p| DANGEROUS_PERMISSIONS.contains(&p.as_str()))
        .cloned()
        .collect();
    Ok((
        ApkPermissions {
            package_name,
            all_permissions: permissions,
            dangerous_permissions,
        },
        skipped,
    ))
}

fn axml_err(msg: &str) -> AndroidError {
    AndroidError::AxmlParseFailed(msg.to_owned())
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    let b = data.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    let b = data.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

// ---------------------------------------------------------------------------
// 문자열 풀
// ---------------------------------------------------------------------------

/// 문자열 풀 (요청 시 디코딩 — 조작된 stringCount 로 인한 과다 할당 방지)
struct StringPool<'a> {
    chunk: &'a [u8],
    count: usize,
    offsets_start: usize,
    strings_start: usize,
    utf8: bool,
}

impl<'a> StringPool<'a> {
    fn new(chunk: &'a [u8], header_size: usize) -> Result<Self, AndroidError> {
        let field = |off| read_u32(chunk, off).ok_or_else(|| axml_err("문자열 풀 헤더가 잘림"));
        let count = field(8)? as usize;
        let flags = field(16)?;
        let strings_start = field(20)? as usize;
        let offsets_start = header_size;
        let offsets_end = count
            .checked_mul(4)
            .and_then(|n| n.checked_add(offsets_start))
            .filter(|&e| e <= chunk.len())
            .ok_or_else(|| axml_err("문자열 풀 오프셋 배열이 청크 범위를 벗어남"))?;
        if count > 0 && (strings_start < offsets_end || strings_start > chunk.len()) {
            return Err(axml_err("문자열 풀 stringsStart 가 비정상"));
        }
        Ok(Self {
            chunk,
            count,
            offsets_start,
            strings_start,
            utf8: flags & STRING_POOL_UTF8_FLAG != 0,
        })
    }

    fn get(&self, idx: u32) -> Option<String> {
        let idx = idx as usize;
        if idx >= self.count {
            return None;
        }
        let rel = read_u32(self.chunk, self.offsets_start + idx * 4)? as usize;
        let start = self.strings_start.checked_add(rel)?;
        if self.utf8 {
            decode_utf8_entry(self.chunk, start)
        } else {
            decode_utf16_entry(self.chunk, start)
        }
    }
}

/// UTF-8 엔트리: [UTF-16 길이(1~2B)] [UTF-8 바이트 길이(1~2B)] [바이트] [0x00]
fn decode_utf8_entry(chunk: &[u8], start: usize) -> Option<String> {
    let (_, p) = read_len8(chunk, start)?;
    let (byte_len, p) = read_len8(chunk, p)?;
    let bytes = chunk.get(p..p.checked_add(byte_len)?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn read_len8(chunk: &[u8], p: usize) -> Option<(usize, usize)> {
    let b0 = *chunk.get(p)?;
    if b0 & 0x80 != 0 {
        let b1 = *chunk.get(p + 1)?;
        Some(((usize::from(b0 & 0x7F) << 8) | usize::from(b1), p + 2))
    } else {
        Some((usize::from(b0), p + 1))
    }
}

/// UTF-16 엔트리: [문자 수(2~4B)] [UTF-16LE 문자들] [0x0000]
fn decode_utf16_entry(chunk: &[u8], start: usize) -> Option<String> {
    let l0 = read_u16(chunk, start)?;
    let (len, p) = if l0 & 0x8000 != 0 {
        let l1 = read_u16(chunk, start + 2)?;
        (
            ((usize::from(l0 & 0x7FFF)) << 16) | usize::from(l1),
            start + 4,
        )
    } else {
        (usize::from(l0), start + 2)
    };
    let bytes = chunk.get(p..p.checked_add(len.checked_mul(2)?)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

// ---------------------------------------------------------------------------
// START_ELEMENT
// ---------------------------------------------------------------------------

struct RawAttr {
    name: u32,
    raw_value: u32,
    data_type: u8,
    data: u32,
}

struct RawElement {
    name: u32,
    attrs: Vec<RawAttr>,
}

/// ResXMLTree_attrExt + ResXMLTree_attribute[] 파싱. 범위 오류 시 None.
fn parse_start_element(chunk: &[u8], header_size: usize) -> Option<RawElement> {
    let ext = header_size;
    let name = read_u32(chunk, ext + 4)?;
    let attr_start = usize::from(read_u16(chunk, ext + 8)?);
    let attr_size = usize::from(read_u16(chunk, ext + 10)?);
    let attr_count = usize::from(read_u16(chunk, ext + 12)?);
    if attr_count > 0 && attr_size < ATTRIBUTE_MIN_SIZE {
        return None;
    }
    let base = ext.checked_add(attr_start)?;
    let attrs_end = attr_count.checked_mul(attr_size)?.checked_add(base)?;
    if attrs_end > chunk.len() {
        return None;
    }
    let attrs = (0..attr_count)
        .map(|i| {
            let a = base + i * attr_size;
            Some(RawAttr {
                name: read_u32(chunk, a + 4)?,
                raw_value: read_u32(chunk, a + 8)?,
                data_type: *chunk.get(a + 15)?,
                data: read_u32(chunk, a + 16)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(RawElement { name, attrs })
}

struct ElementSink<'s> {
    package_name: &'s mut Option<String>,
    saw_manifest: &'s mut bool,
    permissions: &'s mut Vec<String>,
    skipped: &'s mut usize,
}

fn handle_element(elem: &RawElement, pool: &StringPool, res_map: &[u8], sink: &mut ElementSink) {
    let Some(tag) = pool.get(elem.name) else {
        *sink.skipped += 1;
        return;
    };
    match tag.as_str() {
        "manifest" => {
            *sink.saw_manifest = true;
            if sink.package_name.is_some() {
                return;
            }
            let attr = elem
                .attrs
                .iter()
                .find(|a| pool.get(a.name).as_deref() == Some("package"));
            if let Some(attr) = attr {
                match attr_string(attr, pool) {
                    Some(v) => *sink.package_name = Some(v),
                    None => *sink.skipped += 1,
                }
            }
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            let attr = elem.attrs.iter().find(|a| is_name_attr(a, pool, res_map));
            match attr.and_then(|a| attr_string(a, pool)) {
                Some(perm) if !perm.is_empty() => {
                    if !sink.permissions.contains(&perm) {
                        sink.permissions.push(perm);
                    }
                }
                _ => *sink.skipped += 1,
            }
        }
        _ => {}
    }
}

/// android:name 판별 — 속성명 문자열 "name" 또는 리소스 맵의 ID 0x01010003
fn is_name_attr(attr: &RawAttr, pool: &StringPool, res_map: &[u8]) -> bool {
    let by_res_id = attr
        .name
        .checked_mul(4)
        .and_then(|off| read_u32(res_map, off as usize))
        == Some(ATTR_ANDROID_NAME);
    by_res_id || pool.get(attr.name).as_deref() == Some("name")
}

/// 속성 값: rawValue(문자열 풀 인덱스) 우선, 없으면 typed value(TYPE_STRING)
fn attr_string(attr: &RawAttr, pool: &StringPool) -> Option<String> {
    if attr.raw_value != NO_INDEX
        && let Some(s) = pool.get(attr.raw_value)
    {
        return Some(s);
    }
    if attr.data_type == TYPE_STRING {
        return pool.get(attr.data);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_entry_long_length() {
        // 길이 0x0105 를 2바이트로 인코딩
        let mut chunk = vec![0x81, 0x05, 0x81, 0x05];
        chunk.extend(std::iter::repeat_n(b'a', 0x105));
        chunk.push(0);
        let s = decode_utf8_entry(&chunk, 0).unwrap_or_default();
        assert_eq!(s.len(), 0x105);
    }

    #[test]
    fn utf16_entry_out_of_range() {
        // 길이 100 이지만 데이터 없음
        assert!(decode_utf16_entry(&[100, 0], 0).is_none());
        // 4바이트 길이 플래그인데 잘림
        assert!(decode_utf16_entry(&[0x00, 0x80], 0).is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        assert!(matches!(
            parse_manifest(&[0x03, 0x00, 0x09, 0x00, 0, 0, 0, 0]),
            Err(AndroidError::AxmlParseFailed(_))
        ));
        assert!(parse_manifest(&[0x03]).is_err());
    }
}
