use android::apk::parse_manifest;
use android::packages::parse_packages_bytes;
use android::{AndroidError, analyze_apk, parse_packages};
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// packages.xml (텍스트)
// ---------------------------------------------------------------------------

const TEXT_PACKAGES: &str = r#"<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<packages>
    <version sdkVersion="30" databaseVersion="3" />
    <package name="com.android.settings" codePath="/system/priv-app/Settings" ft="17c4f3a2b10" it="17c4f3a2b10" ut="17c4f3a2b10" version="30" userId="1000">
        <sigs count="1" schemeVersion="3"><cert index="0" /></sigs>
        <perms><item name="android.permission.READ_SMS" granted="true" flags="0" /></perms>
    </package>
    <package name="com.evil.app" codePath="/data/app/~~abc==/com.evil.app-1" ft="18b0a1b2c3d" it="18b0a1b2c3d" ut="18b0a1b9999" userId="10123" />
    <updated-package name="com.google.android.gms" codePath="/product/priv-app/GmsCore" it="1" ut="3e8" />
    <package name="com.legacy.app" codePath="/data/app/com.legacy.app-1" firstInstallTime="5265c00" lastUpdateTime="5265c00" />
    <package name="com.broken.app" codePath="/data/app/broken" it="nothex" ut="0" />
    <package codePath="/data/app/noname" it="1" ut="1" />
    <shared-user name="android.uid.system" userId="1000" />
</packages>
"#;

#[test]
fn text_packages_xml() -> Result<(), AndroidError> {
    let (pkgs, skipped) = parse_packages_bytes(TEXT_PACKAGES.as_bytes())?;
    assert_eq!(skipped, 2, "잘못된 16진수 + name 누락");
    assert_eq!(pkgs.len(), 4);

    let settings = &pkgs[0];
    assert_eq!(settings.name, "com.android.settings");
    assert!(settings.is_system);
    assert_eq!(settings.first_install, 0x17c4f3a2b10 / 1000);

    let evil = &pkgs[1];
    assert_eq!(evil.name, "com.evil.app");
    assert!(!evil.is_system);
    assert_eq!(evil.first_install, 0x18b0a1b2c3d / 1000);
    assert_eq!(evil.last_update, 0x18b0a1b9999 / 1000);

    let gms = &pkgs[2];
    assert_eq!(gms.name, "com.google.android.gms");
    assert!(gms.is_system);
    assert_eq!(gms.last_update, 1);

    // 설계 문서 속성명(firstInstallTime/lastUpdateTime) 호환
    let legacy = &pkgs[3];
    assert_eq!(legacy.first_install, 0x5265c00 / 1000);
    assert_eq!(legacy.last_update, 0x5265c00 / 1000);
    Ok(())
}

#[test]
fn text_packages_file_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = tempfile::NamedTempFile::new()?;
    f.write_all(TEXT_PACKAGES.as_bytes())?;
    let pkgs = parse_packages(f.path())?;
    assert_eq!(pkgs.len(), 4);
    Ok(())
}

#[test]
fn text_packages_truncated() {
    let cut = TEXT_PACKAGES.len() / 2;
    let r = parse_packages_bytes(&TEXT_PACKAGES.as_bytes()[..cut]);
    assert!(matches!(r, Err(AndroidError::XmlParseFailed(_))));
}

#[test]
fn text_packages_wrong_root() {
    let r = parse_packages_bytes(b"<foo><package name=\"a\" codePath=\"/data/a\" /></foo>");
    assert!(matches!(r, Err(AndroidError::SchemaMismatch(_))));
}

#[test]
fn text_packages_malformed_xml() {
    let r = parse_packages_bytes(b"<packages><package name=\"a\" codePath=\"/data/a\"></packages>");
    assert!(matches!(r, Err(AndroidError::XmlParseFailed(_))));
}

#[test]
fn packages_missing_file() {
    let r = parse_packages(Path::new("/nonexistent/packages.xml"));
    assert!(matches!(r, Err(AndroidError::OpenFailed { .. })));
}

// ---------------------------------------------------------------------------
// packages.xml (ABX)
// ---------------------------------------------------------------------------

const T_START_DOC: u8 = 0;
const T_END_DOC: u8 = 1;
const T_START_TAG: u8 = 2;
const T_END_TAG: u8 = 3;
const T_ATTR: u8 = 15;
const TY_NULL: u8 = 1 << 4;
const TY_STRING: u8 = 2 << 4;
const TY_INTERNED: u8 = 3 << 4;
const TY_INT: u8 = 6 << 4;
const TY_LONG_HEX: u8 = 9 << 4;
const TY_BOOL_TRUE: u8 = 12 << 4;

/// AOSP BinaryXmlSerializer 형식을 흉내 내는 최소 ABX 작성기
#[derive(Default)]
struct Abx {
    buf: Vec<u8>,
    interned: Vec<String>,
}

impl Abx {
    fn new() -> Self {
        let mut a = Self::default();
        a.buf.extend_from_slice(b"ABX\0");
        a.buf.push(T_START_DOC | TY_NULL);
        a
    }
    fn utf(&mut self, s: &str) {
        self.buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(s.as_bytes());
    }
    fn interned(&mut self, s: &str) {
        if let Some(i) = self.interned.iter().position(|x| x == s) {
            self.buf.extend_from_slice(&(i as u16).to_be_bytes());
        } else {
            self.buf.extend_from_slice(&0xFFFFu16.to_be_bytes());
            self.utf(s);
            self.interned.push(s.to_owned());
        }
    }
    fn start(&mut self, name: &str) -> &mut Self {
        self.buf.push(T_START_TAG | TY_INTERNED);
        self.interned(name);
        self
    }
    fn end(&mut self, name: &str) -> &mut Self {
        self.buf.push(T_END_TAG | TY_INTERNED);
        self.interned(name);
        self
    }
    fn attr_str(&mut self, k: &str, v: &str) -> &mut Self {
        self.buf.push(T_ATTR | TY_STRING);
        self.interned(k);
        self.utf(v);
        self
    }
    fn attr_interned(&mut self, k: &str, v: &str) -> &mut Self {
        self.buf.push(T_ATTR | TY_INTERNED);
        self.interned(k);
        self.interned(v);
        self
    }
    fn attr_long_hex(&mut self, k: &str, v: i64) -> &mut Self {
        self.buf.push(T_ATTR | TY_LONG_HEX);
        self.interned(k);
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn attr_int(&mut self, k: &str, v: i32) -> &mut Self {
        self.buf.push(T_ATTR | TY_INT);
        self.interned(k);
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn attr_bool(&mut self, k: &str) -> &mut Self {
        self.buf.push(T_ATTR | TY_BOOL_TRUE);
        self.interned(k);
        self
    }
    fn finish(&mut self) -> Vec<u8> {
        self.buf.push(T_END_DOC | TY_NULL);
        std::mem::take(&mut self.buf)
    }
}

fn sample_abx() -> Vec<u8> {
    let mut a = Abx::new();
    a.start("packages");
    a.start("version").attr_int("sdkVersion", 34).end("version");
    a.start("package")
        .attr_str("name", "com.android.phone")
        .attr_interned("codePath", "/system/priv-app/TeleService")
        .attr_long_hex("ft", 0x18000000000)
        .attr_long_hex("it", 0x18000000000)
        .attr_long_hex("ut", 0x18000001000)
        .attr_bool("isOrphaned")
        .attr_int("userId", 1001);
    a.start("perms").end("perms");
    a.end("package");
    a.start("package")
        .attr_str("name", "com.evil.app")
        .attr_str("codePath", "/data/app/~~x==/com.evil.app-2")
        .attr_long_hex("it", 0x19000000000)
        .attr_long_hex("ut", 0x19000000000)
        .end("package");
    // name 누락 → 건너뜀
    a.start("package")
        .attr_str("codePath", "/data/app/x")
        .end("package");
    a.end("packages");
    a.finish()
}

#[test]
fn abx_packages_xml() -> Result<(), AndroidError> {
    let (pkgs, skipped) = parse_packages_bytes(&sample_abx())?;
    assert_eq!(skipped, 1);
    assert_eq!(pkgs.len(), 2);
    assert_eq!(pkgs[0].name, "com.android.phone");
    assert_eq!(pkgs[0].code_path, "/system/priv-app/TeleService");
    assert!(pkgs[0].is_system);
    assert_eq!(pkgs[0].first_install, 0x18000000000 / 1000);
    assert_eq!(pkgs[0].last_update, 0x18000001000 / 1000);
    assert_eq!(pkgs[1].name, "com.evil.app");
    assert!(!pkgs[1].is_system);
    assert_eq!(pkgs[1].first_install, 0x19000000000 / 1000);
    Ok(())
}

#[test]
fn abx_truncated() {
    let data = sample_abx();
    for cut in 4..data.len() {
        let r = parse_packages_bytes(&data[..cut]);
        assert!(r.is_err(), "cut={cut} 에서 에러가 나야 함");
    }
}

#[test]
fn abx_bad_interned_index() {
    let mut data = b"ABX\0".to_vec();
    data.push(T_START_DOC | TY_NULL);
    data.push(T_START_TAG | TY_INTERNED);
    data.extend_from_slice(&7u16.to_be_bytes());
    assert!(matches!(
        parse_packages_bytes(&data),
        Err(AndroidError::XmlParseFailed(_))
    ));
}

#[test]
fn abx_unknown_token_type() {
    let mut data = b"ABX\0".to_vec();
    data.push(T_START_DOC | TY_NULL);
    data.push(0xF0 | T_ATTR); // 데이터 타입 15 (정의되지 않음)
    data.extend_from_slice(&0xFFFFu16.to_be_bytes());
    data.extend_from_slice(&1u16.to_be_bytes());
    data.push(b'x');
    assert!(matches!(
        parse_packages_bytes(&data),
        Err(AndroidError::UnsupportedFormat(_))
    ));
}

// ---------------------------------------------------------------------------
// AXML / APK
// ---------------------------------------------------------------------------

const NO_INDEX: u32 = 0xFFFF_FFFF;
const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

enum Val {
    /// rawValue 로 문자열 풀 인덱스 지정
    Raw(&'static str),
    /// rawValue 없이 typed value (TYPE_STRING) 로만 지정
    Typed(&'static str),
    /// 임의의 rawValue 인덱스 (범위 밖 테스트용)
    BadIndex(u32),
}

struct Attr {
    ns: Option<&'static str>,
    name: &'static str,
    val: Val,
}

struct Elem {
    name: &'static str,
    attrs: Vec<Attr>,
}

struct AxmlBuilder {
    strings: Vec<String>,
    utf8: bool,
    elems: Vec<Elem>,
    res_map: Vec<u32>,
}

impl AxmlBuilder {
    fn idx(&mut self, s: &str) -> u32 {
        if let Some(i) = self.strings.iter().position(|x| x == s) {
            return i as u32;
        }
        self.strings.push(s.to_owned());
        (self.strings.len() - 1) as u32
    }

    fn string_pool(&self) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut data = Vec::new();
        for s in &self.strings {
            offsets.push(data.len() as u32);
            if self.utf8 {
                let u16_len = s.encode_utf16().count();
                push_len8(&mut data, u16_len);
                push_len8(&mut data, s.len());
                data.extend_from_slice(s.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                data.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for u in units {
                    data.extend_from_slice(&u.to_le_bytes());
                }
                data.extend_from_slice(&[0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let header = 28u32;
        let strings_start = header + 4 * self.strings.len() as u32;
        let size = strings_start + data.len() as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(header as u16).to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        let flags = if self.utf8 { 0x100u32 } else { 0 };
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&strings_start.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        for o in offsets {
            out.extend_from_slice(&o.to_le_bytes());
        }
        out.extend_from_slice(&data);
        out
    }

    fn build(mut self) -> Vec<u8> {
        let elems = std::mem::take(&mut self.elems);
        let mut body = Vec::new();
        let ns_idx = self.idx(ANDROID_NS);
        let prefix_idx = self.idx("android");
        // START_NAMESPACE
        body.extend(node(0x0100, &[prefix_idx, ns_idx]));
        for e in &elems {
            let name = self.idx(e.name);
            let mut ext = Vec::new();
            ext.extend_from_slice(&NO_INDEX.to_le_bytes()); // ns
            ext.extend_from_slice(&name.to_le_bytes());
            ext.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
            ext.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
            ext.extend_from_slice(&(e.attrs.len() as u16).to_le_bytes());
            ext.extend_from_slice(&[0; 6]); // id/class/style index
            for a in &e.attrs {
                let ns = a.ns.map(|n| self.idx(n)).unwrap_or(NO_INDEX);
                let an = self.idx(a.name);
                let (raw, ty, data) = match a.val {
                    Val::Raw(s) => {
                        let i = self.idx(s);
                        (i, 0x03u8, i)
                    }
                    Val::Typed(s) => (NO_INDEX, 0x03u8, self.idx(s)),
                    Val::BadIndex(i) => (i, 0x10u8, 0),
                };
                ext.extend_from_slice(&ns.to_le_bytes());
                ext.extend_from_slice(&an.to_le_bytes());
                ext.extend_from_slice(&raw.to_le_bytes());
                ext.extend_from_slice(&8u16.to_le_bytes());
                ext.push(0);
                ext.push(ty);
                ext.extend_from_slice(&data.to_le_bytes());
            }
            body.extend(raw_node(0x0102, &ext));
            body.extend(node(0x0103, &[NO_INDEX, name]));
        }
        body.extend(node(0x0101, &[prefix_idx, ns_idx]));

        let mut chunks = self.string_pool();
        if !self.res_map.is_empty() {
            let size = 8 + 4 * self.res_map.len() as u32;
            chunks.extend_from_slice(&0x0180u16.to_le_bytes());
            chunks.extend_from_slice(&8u16.to_le_bytes());
            chunks.extend_from_slice(&size.to_le_bytes());
            for id in &self.res_map {
                chunks.extend_from_slice(&id.to_le_bytes());
            }
        }
        chunks.extend(body);
        let mut out = Vec::new();
        out.extend_from_slice(&3u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&(8 + chunks.len() as u32).to_le_bytes());
        out.extend(chunks);
        out
    }
}

fn push_len8(buf: &mut Vec<u8>, len: usize) {
    if len > 0x7F {
        buf.push(0x80 | (len >> 8) as u8);
        buf.push(len as u8);
    } else {
        buf.push(len as u8);
    }
}

/// XML 트리 노드: header(16) + ext
fn raw_node(ty: u16, ext: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(&(16 + ext.len() as u32).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes()); // lineNumber
    out.extend_from_slice(&NO_INDEX.to_le_bytes()); // comment
    out.extend_from_slice(ext);
    out
}

fn node(ty: u16, words: &[u32]) -> Vec<u8> {
    let ext: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    raw_node(ty, &ext)
}

fn perm(name: &'static str) -> Elem {
    Elem {
        name: "uses-permission",
        attrs: vec![Attr {
            ns: Some(ANDROID_NS),
            name: "name",
            val: Val::Raw(name),
        }],
    }
}

fn sample_manifest(utf8: bool) -> Vec<u8> {
    AxmlBuilder {
        strings: Vec::new(),
        utf8,
        res_map: Vec::new(),
        elems: vec![
            Elem {
                name: "manifest",
                attrs: vec![
                    Attr {
                        ns: Some(ANDROID_NS),
                        name: "versionCode",
                        val: Val::Raw("1"),
                    },
                    Attr {
                        ns: None,
                        name: "package",
                        val: Val::Raw("com.evil.app"),
                    },
                ],
            },
            perm("android.permission.INTERNET"),
            perm("android.permission.READ_SMS"),
            Elem {
                name: "uses-permission-sdk-23",
                attrs: vec![Attr {
                    ns: Some(ANDROID_NS),
                    name: "name",
                    val: Val::Typed("android.permission.CAMERA"),
                }],
            },
            perm("android.permission.READ_SMS"), // 중복
            perm("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            Elem {
                name: "application",
                attrs: vec![],
            },
        ],
    }
    .build()
}

fn check_sample(p: &android::ApkPermissions) {
    assert_eq!(p.package_name, "com.evil.app");
    assert_eq!(
        p.all_permissions,
        vec![
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
    );
    assert_eq!(
        p.dangerous_permissions,
        vec![
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
    );
}

#[test]
fn axml_utf16_pool() -> Result<(), AndroidError> {
    let (p, skipped) = parse_manifest(&sample_manifest(false))?;
    assert_eq!(skipped, 0);
    check_sample(&p);
    Ok(())
}

#[test]
fn axml_utf8_pool() -> Result<(), AndroidError> {
    let (p, skipped) = parse_manifest(&sample_manifest(true))?;
    assert_eq!(skipped, 0);
    check_sample(&p);
    Ok(())
}

#[test]
fn axml_obfuscated_name_attr_by_resource_id() -> Result<(), AndroidError> {
    // 속성명 문자열이 비어 있어도 리소스 맵 ID(0x01010003)로 android:name 인식
    let data = AxmlBuilder {
        // 인덱스 0 = 빈 속성명 (리소스 맵 0번 → android:name)
        strings: vec![String::new()],
        utf8: false,
        res_map: vec![0x0101_0003],
        elems: vec![
            Elem {
                name: "manifest",
                attrs: vec![Attr {
                    ns: None,
                    name: "package",
                    val: Val::Raw("com.obf"),
                }],
            },
            Elem {
                name: "uses-permission",
                attrs: vec![Attr {
                    ns: Some(ANDROID_NS),
                    name: "",
                    val: Val::Raw("android.permission.RECORD_AUDIO"),
                }],
            },
        ],
    }
    .build();
    let (p, _) = parse_manifest(&data)?;
    assert_eq!(p.package_name, "com.obf");
    assert_eq!(
        p.dangerous_permissions,
        vec!["android.permission.RECORD_AUDIO"]
    );
    Ok(())
}

#[test]
fn axml_out_of_range_index_is_skipped() -> Result<(), AndroidError> {
    let data = AxmlBuilder {
        strings: Vec::new(),
        utf8: true,
        res_map: Vec::new(),
        elems: vec![
            Elem {
                name: "manifest",
                attrs: vec![Attr {
                    ns: None,
                    name: "package",
                    val: Val::Raw("com.x"),
                }],
            },
            Elem {
                name: "uses-permission",
                attrs: vec![Attr {
                    ns: Some(ANDROID_NS),
                    name: "name",
                    val: Val::BadIndex(0x00FF_FFFF),
                }],
            },
            perm("android.permission.SEND_SMS"),
        ],
    }
    .build();
    let (p, skipped) = parse_manifest(&data)?;
    assert_eq!(skipped, 1);
    assert_eq!(p.all_permissions, vec!["android.permission.SEND_SMS"]);
    Ok(())
}

#[test]
fn axml_missing_package_attr() {
    let data = AxmlBuilder {
        strings: Vec::new(),
        utf8: false,
        res_map: Vec::new(),
        elems: vec![Elem {
            name: "manifest",
            attrs: vec![],
        }],
    }
    .build();
    assert!(matches!(
        parse_manifest(&data),
        Err(AndroidError::AxmlParseFailed(_))
    ));
}

#[test]
fn axml_bad_magic() {
    let mut data = sample_manifest(false);
    data[0] = 0x05;
    assert!(matches!(
        parse_manifest(&data),
        Err(AndroidError::AxmlParseFailed(_))
    ));
    // 텍스트 XML 매니페스트도 거부
    assert!(parse_manifest(b"<manifest package=\"a\"/>").is_err());
}

#[test]
fn axml_truncated_never_panics() {
    let data = sample_manifest(true);
    for cut in 0..data.len() {
        // 잘린 입력은 에러여야 하며 패닉하지 않아야 함
        let _ = parse_manifest(&data[..cut]);
    }
    // 문자열 풀 청크 중간에서 잘리면 에러
    assert!(parse_manifest(&data[..40]).is_err());
}

#[test]
fn axml_corrupt_chunk_sizes_never_panic() {
    let base = sample_manifest(false);
    // 모든 위치의 바이트를 0xFF / 0x00 으로 바꿔도 패닉하지 않아야 함
    for i in 0..base.len() {
        for v in [0x00u8, 0xFF, 0x7F] {
            let mut d = base.clone();
            d[i] = v;
            let _ = parse_manifest(&d);
        }
    }
}

#[test]
fn axml_huge_string_count_rejected() {
    let mut data = sample_manifest(false);
    // 문자열 풀 stringCount (파일 오프셋 8 + 8)
    data[16..20].copy_from_slice(&0x3FFF_FFFFu32.to_le_bytes());
    assert!(matches!(
        parse_manifest(&data),
        Err(AndroidError::AxmlParseFailed(_))
    ));
}

#[test]
fn axml_zero_chunk_size_rejected() {
    let mut data = sample_manifest(false);
    // 문자열 풀 청크 크기를 0 으로 → 무한 루프가 아닌 에러
    data[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert!(parse_manifest(&data).is_err());
}

fn write_apk(
    dir: &Path,
    manifest: Option<&[u8]>,
    method: zip::CompressionMethod,
) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join("test.apk");
    let file = std::fs::File::create(&path)?;
    let mut zw = zip::ZipWriter::new(file);
    let opts = zip::write::SimpleFileOptions::default().compression_method(method);
    zw.start_file("classes.dex", opts)?;
    zw.write_all(b"dex\n035\0")?;
    if let Some(m) = manifest {
        zw.start_file("AndroidManifest.xml", opts)?;
        zw.write_all(m)?;
    }
    zw.finish()?;
    Ok(path)
}

#[test]
fn apk_end_to_end_deflate_and_stored() -> Result<(), Box<dyn std::error::Error>> {
    for method in [
        zip::CompressionMethod::Deflated,
        zip::CompressionMethod::Stored,
    ] {
        let dir = tempfile::tempdir()?;
        let path = write_apk(dir.path(), Some(&sample_manifest(true)), method)?;
        let p = analyze_apk(&path)?;
        check_sample(&p);
    }
    Ok(())
}

#[test]
fn apk_without_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = write_apk(dir.path(), None, zip::CompressionMethod::Deflated)?;
    assert!(matches!(analyze_apk(&path), Err(AndroidError::ZipError(_))));
    Ok(())
}

#[test]
fn apk_not_a_zip() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = tempfile::NamedTempFile::new()?;
    f.write_all(b"definitely not a zip file")?;
    assert!(matches!(
        analyze_apk(f.path()),
        Err(AndroidError::ZipError(_))
    ));
    Ok(())
}

#[test]
fn apk_manifest_size_limit() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let big = vec![0u8; (android::apk::MAX_MANIFEST_SIZE + 10) as usize];
    let path = write_apk(dir.path(), Some(&big), zip::CompressionMethod::Deflated)?;
    assert!(matches!(
        analyze_apk(&path),
        Err(AndroidError::UnsupportedFormat(_))
    ));
    Ok(())
}

#[test]
fn apk_missing_file() {
    let r = analyze_apk(Path::new("/nonexistent/x.apk"));
    assert!(matches!(r, Err(AndroidError::OpenFailed { .. })));
}
