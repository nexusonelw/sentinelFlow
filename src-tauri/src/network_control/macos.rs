use std::{path::Path, process::Command};

const FIREWALL: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

pub fn block(executable: &str) -> Result<(), String> {
    if !Path::new(FIREWALL).exists() {
        return Err("当前 macOS 系统缺少 Application Firewall 管理工具".to_string());
    }
    let global_state = Command::new(FIREWALL)
        .arg("--getglobalstate")
        .output()
        .map_err(|error| format!("无法读取 macOS 防火墙状态：{error}"))?;
    let state_text = format!(
        "{}{}",
        String::from_utf8_lossy(&global_state.stdout),
        String::from_utf8_lossy(&global_state.stderr)
    );
    if state_text.contains("State = 0") {
        return Err(
            "macOS 系统防火墙当前处于关闭状态；请先在系统设置的“网络 > 防火墙”中启用".to_string(),
        );
    }
    let target = application_target(executable);
    let command = format!(
        "{FIREWALL} --add {} >/dev/null 2>&1 || true; if {FIREWALL} --blockapp {}; then exit 0; else {FIREWALL} --remove {} >/dev/null 2>&1 || true; exit 1; fi",
        shell_quote(&target),
        shell_quote(&target),
        shell_quote(&target)
    );
    run_as_administrator(&command)
}

pub fn unblock(executable: &str) -> Result<(), String> {
    let target = application_target(executable);
    let command = format!(
        "{FIREWALL} --unblockapp {} >/dev/null 2>&1 || true; {FIREWALL} --remove {} >/dev/null 2>&1 || true",
        shell_quote(&target),
        shell_quote(&target)
    );
    run_as_administrator(&command)
}

fn application_target(executable: &str) -> String {
    let path = Path::new(executable);
    for ancestor in path.ancestors() {
        if ancestor
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"))
        {
            return ancestor.to_string_lossy().into_owned();
        }
    }
    executable.to_string()
}

fn run_as_administrator(command: &str) -> Result<(), String> {
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        apple_script_escape(command)
    );
    let output = Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .map_err(|error| format!("无法打开 macOS 管理员授权窗口：{error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if message.contains("(-128)") || message.to_lowercase().contains("user canceled") {
        Err("已取消管理员授权，网络状态未更改".to_string())
    } else {
        Err(format!("macOS 防火墙操作失败：{message}"))
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn apple_script_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
