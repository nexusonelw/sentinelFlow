use base64::{engine::general_purpose::STANDARD, Engine};
use std::process::Command;

const RULE_DIRECTORY: &str = "/etc/sentinel-flow/network-blocks";
const GUARD_PATH: &str = "/usr/local/libexec/sentinel-flow-network-guard";
const UNIT_PATH: &str = "/etc/systemd/system/sentinel-flow-network-guard.service";

const GUARD_SCRIPT: &str = r#"#!/bin/sh
set -eu
RULE_DIR=/etc/sentinel-flow/network-blocks
CGROUP_ROOT=/sys/fs/cgroup/sentinel-flow
CHAIN=SENTINEL_FLOW
mkdir -p "$RULE_DIR" "$CGROUP_ROOT"
iptables -N "$CHAIN" 2>/dev/null || true
iptables -C OUTPUT -j "$CHAIN" 2>/dev/null || iptables -I OUTPUT 1 -j "$CHAIN"
rebuild_rules() {
  iptables -F "$CHAIN"
  for rule in "$RULE_DIR"/*; do
    [ -f "$rule" ] || continue
    key=$(basename "$rule")
    mkdir -p "$CGROUP_ROOT/$key"
    iptables -A "$CHAIN" -m cgroup --path "sentinel-flow/$key" -j REJECT
  done
}
rebuild_rules
while :; do
  for rule in "$RULE_DIR"/*; do
    [ -f "$rule" ] || continue
    key=$(basename "$rule")
    wanted=$(cat "$rule")
    for link in /proc/[0-9]*/exe; do
      actual=$(readlink "$link" 2>/dev/null || true)
      [ "$actual" = "$wanted" ] || continue
      pid=${link#/proc/}; pid=${pid%/exe}
      printf '%s\n' "$pid" > "$CGROUP_ROOT/$key/cgroup.procs" 2>/dev/null || true
    done
  done
  sleep 1
done
"#;

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=Sentinel Flow persistent per-application network guard
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/libexec/sentinel-flow-network-guard
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
"#;

pub fn block(executable: &str, identifier: &str, pid: u32) -> Result<(), String> {
    ensure_supported()?;
    let key = identifier.to_lowercase();
    let setup = format!(
        "set -e; install -d -m 755 /usr/local/libexec {rule_dir}; printf %s {guard} | base64 -d > {guard_path}; chmod 755 {guard_path}; printf %s {unit} | base64 -d > {unit_path}; printf '%s\\n' {executable} > {rule_dir}/{key}; chmod 600 {rule_dir}/{key}; systemctl daemon-reload; systemctl enable --now sentinel-flow-network-guard.service; systemctl restart sentinel-flow-network-guard.service; if [ {pid} -gt 0 ]; then mkdir -p /sys/fs/cgroup/sentinel-flow/{key}; printf '%s\\n' {pid} > /sys/fs/cgroup/sentinel-flow/{key}/cgroup.procs || true; fi",
        rule_dir = shell_quote(RULE_DIRECTORY),
        guard = shell_quote(&STANDARD.encode(GUARD_SCRIPT)),
        guard_path = shell_quote(GUARD_PATH),
        unit = shell_quote(&STANDARD.encode(SYSTEMD_UNIT)),
        unit_path = shell_quote(UNIT_PATH),
        executable = shell_quote(executable),
        key = shell_quote(&key),
        pid = pid,
    );
    run_pkexec(&setup)
}

pub fn unblock(identifier: &str) -> Result<(), String> {
    ensure_supported()?;
    let key = identifier.to_lowercase();
    let cleanup = format!(
        "set -e; rm -f {rule_dir}/{key}; if find {rule_dir} -mindepth 1 -maxdepth 1 -type f | grep -q .; then systemctl restart sentinel-flow-network-guard.service; else systemctl disable --now sentinel-flow-network-guard.service || true; iptables -D OUTPUT -j SENTINEL_FLOW 2>/dev/null || true; iptables -F SENTINEL_FLOW 2>/dev/null || true; iptables -X SENTINEL_FLOW 2>/dev/null || true; fi; rmdir /sys/fs/cgroup/sentinel-flow/{key} 2>/dev/null || true",
        rule_dir = shell_quote(RULE_DIRECTORY),
        key = shell_quote(&key),
    );
    run_pkexec(&cleanup)
}

fn ensure_supported() -> Result<(), String> {
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err("Linux 网络封禁需要 cgroup v2；当前系统未启用".to_string());
    }
    for command in ["pkexec", "systemctl", "iptables", "base64"] {
        let status = Command::new("sh")
            .args(["-c", &format!("command -v {command} >/dev/null 2>&1")])
            .status()
            .map_err(|error| format!("无法检查 Linux 系统组件：{error}"))?;
        if !status.success() {
            return Err(format!("Linux 网络封禁缺少必要组件：{command}"));
        }
    }
    Ok(())
}

fn run_pkexec(script: &str) -> Result<(), String> {
    let output = Command::new("pkexec")
        .args(["/bin/sh", "-c", script])
        .output()
        .map_err(|error| format!("无法打开 PolicyKit 管理员授权窗口：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if message.is_empty() {
            "Linux 网络封禁未完成（可能取消了管理员授权）".to_string()
        } else {
            format!("Linux 网络封禁失败：{message}")
        })
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
