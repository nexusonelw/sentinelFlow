use crate::models::{
    MonitorCoverage, NetworkConnectionDetail, NetworkCounters, OpenFileEvidence,
    PlatformProcessDetail, PlatformSample, TlsInspection,
};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn collect() -> PlatformSample {
    let connection_details = collect_all_connection_details();
    let connections = connection_details
        .iter()
        .map(|(pid, details)| {
            let mut targets = Vec::new();
            for detail in details {
                if !targets.contains(&detail.remote_endpoint) && targets.len() < 8 {
                    targets.push(detail.remote_endpoint.clone());
                }
            }
            (*pid, targets)
        })
        .collect();
    PlatformSample {
        counters: collect_process_bytes(),
        connections,
        connection_details,
    }
}

pub fn coverage() -> MonitorCoverage {
    MonitorCoverage {
        network: "active".to_string(),
        process: "active".to_string(),
        file: "limited".to_string(),
        collector: "macOS 原生进程与文件证据采集器".to_string(),
        note: "通过 nettop、进程表与 lsof 被动观测真实流量、命令行、进程链、连接和有意义的文件句柄。文件句柄不是上传证明；HTTPS 正文只有在目标进程启动前导出 TLS 会话密钥并配合抓包时才可进一步解密。".to_string(),
    }
}

pub fn inspect_process(
    pid: u32,
    command_line: &[String],
    cwd: Option<&Path>,
) -> PlatformProcessDetail {
    let connections = collect_connection_details(pid);
    let mut open_files = collect_open_files(pid);
    merge_command_file_evidence(&mut open_files, command_line, cwd);
    let tls_inspection = inspect_tls(pid, &connections);

    let mut notes = Vec::new();
    if open_files.is_empty() {
        notes.push(
            "没有发现可展示的项目文件句柄；文件可能已被读入内存、已经关闭，或受系统权限限制。"
                .to_string(),
        );
    }
    if tls_inspection.detected {
        notes.push(tls_inspection.note.clone());
    }
    notes.push(
        "网络字节来自 nettop 的进程级计数；当前采集没有读取应用层明文，也没有文件读取到 socket 发送的因果链。"
            .to_string(),
    );

    PlatformProcessDetail {
        connections,
        open_files,
        tls_inspection,
        notes,
    }
}

fn collect_process_bytes() -> HashMap<u32, NetworkCounters> {
    let mut result = HashMap::new();
    let Ok(output) = Command::new("/usr/bin/nettop")
        .args(["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"])
        .output()
    else {
        return result;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        let mut columns = line.trim_end_matches(',').split(',');
        let Some(process_key) = columns.next() else {
            continue;
        };
        let Some(download) = columns.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some(upload) = columns.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let Some((_, pid_text)) = process_key.rsplit_once('.') else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<u32>() else {
            continue;
        };
        result.insert(
            pid,
            NetworkCounters {
                upload_total: upload,
                download_total: download,
            },
        );
    }
    result
}

fn collect_all_connection_details() -> HashMap<u32, Vec<NetworkConnectionDetail>> {
    let mut result: HashMap<u32, Vec<NetworkConnectionDetail>> = HashMap::new();
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-iTCP", "-iUDP"])
        .output()
    else {
        return result;
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines().skip(1) {
        let columns: Vec<&str> = line.split_whitespace().collect();
        if columns.len() < 9 {
            continue;
        }
        let Ok(pid) = columns[1].parse::<u32>() else {
            continue;
        };
        let endpoint = columns[8];
        if endpoint.contains("(LISTEN)") || endpoint.starts_with("*:") {
            continue;
        }
        let Some((local, remote)) = endpoint.split_once("->") else {
            continue;
        };
        let detail = NetworkConnectionDetail {
            protocol: columns.get(7).copied().unwrap_or("IP").to_string(),
            local_endpoint: local.to_string(),
            remote_endpoint: remote.to_string(),
            state: columns
                .iter()
                .skip(9)
                .find_map(|column| {
                    column
                        .strip_prefix('(')
                        .and_then(|value| value.strip_suffix(')'))
                })
                .unwrap_or("ACTIVE")
                .to_string(),
            is_alive: true,
            ..NetworkConnectionDetail::default()
        };
        let details = result.entry(pid).or_default();
        if !details.iter().any(|existing| {
            existing.protocol == detail.protocol
                && existing.local_endpoint == detail.local_endpoint
                && existing.remote_endpoint == detail.remote_endpoint
        }) {
            details.push(detail);
        }
    }
    result
}

#[derive(Default)]
struct RawOpenFile {
    descriptor: String,
    access_mode: String,
    file_type: String,
    offset_bytes: Option<u64>,
    path: String,
}

fn collect_open_files(pid: u32) -> Vec<OpenFileEvidence> {
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args(["-a", "-p", &pid.to_string(), "-nP", "-o", "-Ffatson0"])
        .output()
    else {
        return Vec::new();
    };

    parse_open_file_fields(&output.stdout)
}

fn parse_open_file_fields(output: &[u8]) -> Vec<OpenFileEvidence> {
    let mut result = Vec::new();
    let mut current: Option<RawOpenFile> = None;

    for token in output.split(|byte| *byte == 0 || *byte == b'\n') {
        if token.is_empty() {
            continue;
        }
        let tag = token[0] as char;
        let value = String::from_utf8_lossy(&token[1..]).into_owned();
        if tag == 'f' {
            if let Some(file) = current.take() {
                push_open_file(&mut result, file);
            }
            current = Some(RawOpenFile {
                descriptor: value,
                ..RawOpenFile::default()
            });
            continue;
        }
        let Some(file) = current.as_mut() else {
            continue;
        };
        match tag {
            'a' => file.access_mode = value,
            't' => file.file_type = value,
            'o' => file.offset_bytes = parse_lsof_number(&value),
            'n' => file.path = value,
            _ => {}
        }
    }
    if let Some(file) = current {
        push_open_file(&mut result, file);
    }
    result
}

fn push_open_file(result: &mut Vec<OpenFileEvidence>, file: RawOpenFile) {
    if file.file_type != "REG" || !is_meaningful_path(&file.path, &file.descriptor) {
        return;
    }
    let size_bytes = fs::metadata(&file.path).ok().map(|metadata| metadata.len());
    let category = file_category(&file.path);
    result.push(OpenFileEvidence {
        path: file.path,
        descriptor: file.descriptor,
        access_mode: access_label(&file.access_mode).to_string(),
        file_type: file.file_type,
        size_bytes,
        offset_bytes: file.offset_bytes,
        category,
        evidence: "进程当前持有此文件句柄（未证明与网络发送有因果关系）".to_string(),
        // A handle snapshot is not a data-flow event. Keep the legacy field for
        // frontend compatibility, but never promote it to an upload claim.
        likely_upload_source: false,
    });
}

fn merge_command_file_evidence(
    files: &mut Vec<OpenFileEvidence>,
    command_line: &[String],
    cwd: Option<&Path>,
) {
    let interpreter = command_line.first().map(|value| value.to_lowercase());
    let launch_argument = interpreter
        .filter(|value| {
            ["python", "node", "deno", "bun", "ruby", "perl"]
                .iter()
                .any(|name| value.contains(name))
        })
        .and_then(|_| {
            command_line
                .iter()
                .skip(1)
                .find(|argument| is_script_path(argument))
        });
    for argument in command_line.iter().skip(1) {
        let value = argument
            .split_once('=')
            .map(|(_, value)| value)
            .unwrap_or(argument);
        if value.starts_with("http://") || value.starts_with("https://") || value.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(value);
        let path = if candidate.is_absolute() {
            candidate
        } else if let Some(cwd) = cwd {
            cwd.join(candidate)
        } else {
            continue;
        };
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() || !is_meaningful_path(&path.to_string_lossy(), "argv") {
            continue;
        }
        let normalized = fs::canonicalize(&path).unwrap_or(path);
        let path_text = normalized.to_string_lossy().into_owned();
        let category = file_category(&path_text);
        let is_launch_target = launch_argument.is_some_and(|launch| launch == argument);
        let evidence = if is_launch_target {
            "当前进程的执行脚本（不是上传内容证据）"
        } else {
            "完整启动命令直接引用此文件（不是上传证明）"
        };
        if let Some(existing) = files.iter_mut().find(|file| {
            fs::canonicalize(&file.path).unwrap_or_else(|_| PathBuf::from(&file.path)) == normalized
        }) {
            existing.evidence = if is_launch_target {
                evidence.to_string()
            } else {
                "进程当前持有此文件；完整启动命令也直接引用".to_string()
            };
            existing.likely_upload_source = false;
            continue;
        }
        files.push(OpenFileEvidence {
            path: path_text.clone(),
            descriptor: "argv".to_string(),
            access_mode: "命令参数".to_string(),
            file_type: "REG".to_string(),
            size_bytes: Some(metadata.len()),
            offset_bytes: None,
            category,
            evidence: evidence.to_string(),
            likely_upload_source: false,
        });
    }
    files.sort_by(|left, right| {
        right
            .likely_upload_source
            .cmp(&left.likely_upload_source)
            .then_with(|| right.size_bytes.cmp(&left.size_bytes))
            .then_with(|| left.path.cmp(&right.path))
    });
    files.truncate(40);
}

fn is_script_path(argument: &str) -> bool {
    let lower = argument.to_lowercase();
    [
        ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".sh", ".rb", ".pl",
    ]
    .iter()
    .any(|extension| lower.ends_with(extension))
}

fn is_meaningful_path(path: &str, descriptor: &str) -> bool {
    if !path.starts_with('/') || matches!(descriptor, "cwd" | "txt" | "rtd") {
        return false;
    }
    let lower = path.to_lowercase();
    let ignored_prefixes = [
        "/system/",
        "/usr/lib/",
        "/dev/",
        "/private/var/db/",
        "/library/apple/",
        "/private/etc/",
        "/etc/",
    ];
    let ignored_fragments = [
        "/contents/frameworks/",
        "/contents/resources/",
        "/node_modules/",
        "/.venv/lib/",
        "/site-packages/",
        "/application support/talktunnel/",
        "/dawncache/",
        "/gpucache/",
        "/code cache/",
        "/local storage/",
        "/session storage/",
        "/sharedstorage/",
        "/indexeddb/",
        "/crashpad/",
    ];
    let ignored_suffixes = [".asar", ".dylib", ".so", ".pyc", ".framework", ".lock"];
    !ignored_prefixes
        .iter()
        .any(|prefix| lower.starts_with(prefix))
        && !ignored_fragments
            .iter()
            .any(|fragment| lower.contains(fragment))
        && !ignored_suffixes
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        && !matches!(
            Path::new(path).file_name().and_then(|name| name.to_str()),
            Some("SharedStorage" | "LOG" | "MANIFEST-000001")
        )
}

fn file_category(path: &str) -> String {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_lowercase();
    let label = match extension.as_str() {
        "mp4" | "mov" | "mkv" | "avi" | "flv" | "webm" | "m4v" | "mp3" | "wav" | "aac" | "flac"
        | "m4a" => "音视频",
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "heic" | "svg" => "图片",
        "zip" | "7z" | "rar" | "tar" | "gz" | "bz2" | "xz" => "压缩包",
        "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "md" | "txt" | "rtf" => "文档",
        "json" | "jsonl" | "csv" | "tsv" | "parquet" | "sqlite" | "db" => "数据文件",
        "py" | "js" | "jsx" | "ts" | "tsx" | "rs" | "go" | "java" | "c" | "cc" | "cpp" | "h"
        | "hpp" | "sh" => "源代码",
        "log" => "运行日志",
        "tmp" | "temp" | "cache" => "缓存/临时文件",
        "yaml" | "yml" | "toml" | "ini" | "conf" | "env" => "配置文件",
        _ => "其他文件",
    };
    label.to_string()
}

fn access_label(mode: &str) -> &'static str {
    match mode {
        "r" => "读取",
        "w" => "写入",
        "u" => "读写",
        _ => "未知",
    }
}

fn parse_lsof_number(value: &str) -> Option<u64> {
    value
        .strip_prefix("0t")
        .and_then(|number| number.parse().ok())
        .or_else(|| {
            value
                .strip_prefix("0x")
                .and_then(|number| u64::from_str_radix(number, 16).ok())
        })
        .or_else(|| value.parse().ok())
}

fn inspect_tls(pid: u32, connections: &[NetworkConnectionDetail]) -> TlsInspection {
    let detected = connections.iter().any(|connection| {
        connection.protocol.eq_ignore_ascii_case("TCP")
            && (connection.remote_endpoint.ends_with(":443")
                || connection.remote_endpoint.ends_with(":8443"))
    });
    if !detected {
        return TlsInspection {
            state: "未检测到 TLS 端点".to_string(),
            method: "仅进程连接元数据".to_string(),
            note: "当前没有识别到常见的 TLS 端口；连接元数据仍不包含应用层正文。".to_string(),
            ..TlsInspection::default()
        };
    }

    let keylog_path = process_ssl_keylog_path(pid);
    if let Some(path) = keylog_path.as_ref() {
        let has_keys = fs::metadata(path)
            .map(|metadata| metadata.len() > 0)
            .unwrap_or(false);
        if has_keys {
            return TlsInspection {
                detected: true,
                state: "已发现 TLS 会话密钥日志".to_string(),
                method: "SSLKEYLOGFILE；仍需对应抓包".to_string(),
                keylog_path: Some(path.clone()),
                plaintext_available: false,
                note: "目标进程导出了 TLS 会话密钥，但本采集器尚未拿到对应抓包，因此不会把它标成已解密。".to_string(),
            };
        }
    }

    TlsInspection {
        detected: true,
        state: "TLS 已检测，未发现会话密钥".to_string(),
        method: "仅 nettop/lsof 被动观测".to_string(),
        keylog_path,
        plaintext_available: false,
        note: "检测到 TLS 连接：可以确认端点和字节量，但当前进程没有可用的 SSLKEYLOGFILE，会话正文不能从被动采集中解密。".to_string(),
    }
}

fn process_ssl_keylog_path(pid: u32) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["eww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    let command = String::from_utf8_lossy(&output.stdout);
    command.split_whitespace().find_map(|token| {
        let value = token.strip_prefix("SSLKEYLOGFILE=")?;
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

#[derive(Default)]
struct RawConnection {
    protocol: String,
    endpoint: String,
    state: String,
}

fn collect_connection_details(pid: u32) -> Vec<NetworkConnectionDetail> {
    let Ok(output) = Command::new("/usr/sbin/lsof")
        .args([
            "-a",
            "-p",
            &pid.to_string(),
            "-nP",
            "-iTCP",
            "-iUDP",
            "-FfPTn0",
        ])
        .output()
    else {
        return Vec::new();
    };
    parse_connection_fields(&output.stdout)
}

fn parse_connection_fields(output: &[u8]) -> Vec<NetworkConnectionDetail> {
    let mut result = Vec::new();
    let mut current: Option<RawConnection> = None;
    for token in output.split(|byte| *byte == 0 || *byte == b'\n') {
        if token.is_empty() {
            continue;
        }
        let tag = token[0] as char;
        let value = String::from_utf8_lossy(&token[1..]).into_owned();
        if tag == 'f' {
            if let Some(connection) = current.take() {
                push_connection(&mut result, connection);
            }
            current = Some(RawConnection::default());
            continue;
        }
        let Some(connection) = current.as_mut() else {
            continue;
        };
        match tag {
            'P' => connection.protocol = value,
            'n' => connection.endpoint = value,
            'T' if value.starts_with("ST=") => connection.state = value[3..].to_string(),
            _ => {}
        }
    }
    if let Some(connection) = current {
        push_connection(&mut result, connection);
    }
    result
}

fn push_connection(result: &mut Vec<NetworkConnectionDetail>, connection: RawConnection) {
    let Some((local, remote)) = connection.endpoint.split_once("->") else {
        return;
    };
    if remote.is_empty() {
        return;
    }
    let detail = NetworkConnectionDetail {
        protocol: if connection.protocol.is_empty() {
            "IP".to_string()
        } else {
            connection.protocol
        },
        local_endpoint: local.to_string(),
        remote_endpoint: remote.to_string(),
        state: if connection.state.is_empty() {
            "ACTIVE".to_string()
        } else {
            connection.state
        },
        is_alive: true,
        ..NetworkConnectionDetail::default()
    };
    if !result.iter().any(|existing| {
        existing.protocol == detail.protocol
            && existing.local_endpoint == detail.local_endpoint
            && existing.remote_endpoint == detail.remote_endpoint
    }) {
        result.push(detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_file_fields_and_filters_runtime_libraries() {
        let data = b"p42\0\nf12r\0ar\0tREG\0o0t4096\0n/Users/me/project/video.mp4\0\nftxt\0tREG\0n/usr/lib/libSystem.dylib\0\nf13r\0ar\0tREG\0n/Applications/TalkTunnel.app/Contents/Resources/app.asar\0\nf14u\0au\0tREG\0n/Users/nexusone/Library/Application Support/talktunnel/DawnCache/data_1\0\nf15r\0ar\0tREG\0n/private/etc/hosts\0\n";
        let files = parse_open_file_fields(data);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "/Users/me/project/video.mp4");
        assert_eq!(files[0].offset_bytes, Some(4096));
        assert_eq!(files[0].category, "音视频");
        assert!(!files[0].likely_upload_source);
        assert!(files[0].evidence.contains("未证明"));
    }

    #[test]
    fn parses_established_connection_fields() {
        let data = b"p42\0\nf9u\0PTCP\0n127.0.0.1:51500->203.0.113.8:443\0TST=ESTABLISHED\0\n";
        let connections = parse_connection_fields(data);
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].remote_endpoint, "203.0.113.8:443");
        assert_eq!(connections[0].state, "ESTABLISHED");
    }
}
