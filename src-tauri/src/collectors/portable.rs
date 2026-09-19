use crate::models::{MonitorCoverage, PlatformProcessDetail, PlatformSample, TlsInspection};
use std::path::Path;

pub fn collect() -> PlatformSample {
    // The portable collector intentionally returns no byte estimates. The process
    // graph still works through sysinfo, while the native WFP/eBPF adapters can be
    // added behind this interface without ever presenting fabricated traffic.
    PlatformSample::default()
}

pub fn coverage() -> MonitorCoverage {
    let platform = std::env::consts::OS;
    let collector = if platform == "windows" {
        "Windows 安全降级模式（WFP 适配器待启用）"
    } else {
        "Linux 安全降级模式（eBPF 适配器待启用）"
    };
    MonitorCoverage {
        network: "limited".to_string(),
        process: "active".to_string(),
        file: "permission_required".to_string(),
        collector: collector.to_string(),
        note: "进程生命周期已经启用；在原生 WFP/eBPF 采集器启用前，界面不会猜测或伪造每个进程的网络字节数。监控保持只读，不会干扰现有 VPN、代理或网络连接。".to_string(),
    }
}

pub fn inspect_process(
    _pid: u32,
    _command_line: &[String],
    _cwd: Option<&Path>,
) -> PlatformProcessDetail {
    PlatformProcessDetail {
        tls_inspection: TlsInspection {
            state: "当前平台未启用 TLS 采集器".to_string(),
            method: "无应用层采集".to_string(),
            note: "当前平台只保留进程级安全降级状态，不能读取或解密网络正文。".to_string(),
            ..TlsInspection::default()
        },
        notes: vec!["当前平台尚未启用进程级文件句柄与连接详情采集器。".to_string()],
        ..PlatformProcessDetail::default()
    }
}
