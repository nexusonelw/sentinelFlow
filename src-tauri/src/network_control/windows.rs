use base64::{engine::general_purpose::STANDARD, Engine};
use std::process::Command;

pub fn block(executable: &str, identifier: &str) -> Result<(), String> {
    let path = ps_quote(executable);
    let out_name = ps_quote(&format!("{identifier}_Out"));
    let in_name = ps_quote(&format!("{identifier}_In"));
    let script = format!(
        "$ErrorActionPreference='Stop'; $names=@({out_name},{in_name}); try {{ Remove-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName {out_name} -Group 'Sentinel Flow' -Direction Outbound -Action Block -Program {path} -Profile Any -Enabled True | Out-Null; New-NetFirewallRule -DisplayName {in_name} -Group 'Sentinel Flow' -Direction Inbound -Action Block -Program {path} -Profile Any -Enabled True | Out-Null }} catch {{ Remove-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue; throw }}"
    );
    run_elevated(&script)
}

pub fn unblock(identifier: &str) -> Result<(), String> {
    let out_name = ps_quote(&format!("{identifier}_Out"));
    let in_name = ps_quote(&format!("{identifier}_In"));
    run_elevated(&format!(
        "$ErrorActionPreference='Stop'; Remove-NetFirewallRule -DisplayName {out_name},{in_name} -ErrorAction SilentlyContinue"
    ))
}

fn run_elevated(script: &str) -> Result<(), String> {
    let encoded = encode_powershell(script);
    let launcher = format!(
        "$p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand','{encoded}') -Wait -PassThru; exit $p.ExitCode"
    );
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .output()
        .map_err(|error| format!("无法打开 Windows UAC 授权窗口：{error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(if message.is_empty() {
            "Windows 防火墙操作未完成（可能取消了 UAC 授权）".to_string()
        } else {
            format!("Windows 防火墙操作失败：{message}")
        })
    }
}

fn encode_powershell(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    STANDARD.encode(bytes)
}

fn ps_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
