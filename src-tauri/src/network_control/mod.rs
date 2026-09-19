use crate::models::{BlockedNetworkRule, MonitorSnapshot};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use sysinfo::{Pid, System};
use tauri::Manager;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// These backends only use portable std APIs. Compiling all of them in tests catches syntax and
// type regressions even when CI is running on a single desktop operating system.
#[cfg(all(test, not(target_os = "linux")))]
#[path = "linux.rs"]
#[allow(dead_code)]
mod linux_compile_check;
#[cfg(all(test, not(target_os = "windows")))]
#[path = "windows.rs"]
#[allow(dead_code)]
mod windows_compile_check;

pub struct NetworkBlockManager {
    path: PathBuf,
    rules: Vec<BlockedNetworkRule>,
    active_paths: HashSet<String>,
}

impl NetworkBlockManager {
    pub fn load(app: &tauri::AppHandle) -> Result<Self, String> {
        let directory = app
            .path()
            .app_config_dir()
            .map_err(|error| format!("无法访问应用配置目录：{error}"))?;
        let path = directory.join("blocked_network_rules.json");
        let rules = match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content)
                .map_err(|error| format!("网络封禁规则文件已损坏：{error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(format!("无法读取网络封禁规则：{error}")),
        };
        let mut manager = Self {
            path,
            rules,
            active_paths: HashSet::new(),
        };
        manager.rebuild_active_path_index();
        Ok(manager)
    }

    pub fn annotate_snapshot(&self, snapshot: &mut MonitorSnapshot) {
        for process in &mut snapshot.processes {
            process.is_network_blocked =
                !process.executable.is_empty() && self.is_active_path(&process.executable);
        }
    }

    pub fn block(&mut self, executable: &str, process_name: &str, pid: u32) -> Result<(), String> {
        let normalized = normalize_path(executable)?;
        if self.is_active_path(&normalized) {
            return Ok(());
        }

        let id = rule_id(&normalized);
        let identifier = format!("SentinelFlow_{id}");
        platform_block(&normalized, &identifier, pid)?;

        self.index_path(&normalized);
        self.rules.push(BlockedNetworkRule {
            id,
            executable: normalized.clone(),
            process_name: process_name.to_string(),
            platform: std::env::consts::OS.to_string(),
            rule_identifier: identifier.clone(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            active: true,
        });
        if let Err(error) = self.save() {
            self.rules.pop();
            self.remove_indexed_path(&normalized);
            let _ = platform_unblock(executable, &identifier);
            return Err(error);
        }
        Ok(())
    }

    pub fn unblock(&mut self, executable: &str) -> Result<(), String> {
        let path = Path::new(executable);
        if !path.is_absolute() {
            return Err("网络封禁规则中的可执行文件路径无效".to_string());
        }
        let normalized = normalize_path_for_compare(executable);
        let index = self
            .rules
            .iter()
            .position(|rule| rule.active && paths_equal(&rule.executable, &normalized))
            .ok_or_else(|| "没有找到该程序的持久化封禁规则".to_string())?;
        let rule = self.rules[index].clone();
        platform_unblock(&rule.executable, &rule.rule_identifier)?;
        self.rules.remove(index);
        self.remove_indexed_path(&rule.executable);
        if let Err(error) = self.save() {
            self.rules.insert(index, rule.clone());
            self.index_path(&rule.executable);
            let _ = platform_block(&rule.executable, &rule.rule_identifier, 0);
            return Err(error);
        }
        Ok(())
    }

    fn rebuild_active_path_index(&mut self) {
        self.active_paths.clear();
        let paths: Vec<String> = self
            .rules
            .iter()
            .filter(|rule| rule.active)
            .map(|rule| rule.executable.clone())
            .collect();
        for path in paths {
            self.index_path(&path);
        }
    }

    fn index_path(&mut self, path: &str) {
        self.active_paths.insert(raw_path_key(path));
        self.active_paths.insert(normalize_path_for_compare(path));
    }

    fn remove_indexed_path(&mut self, path: &str) {
        self.active_paths.remove(&raw_path_key(path));
        self.active_paths.remove(&normalize_path_for_compare(path));
    }

    fn is_active_path(&self, executable: &str) -> bool {
        if self.active_paths.contains(&raw_path_key(executable)) {
            return true;
        }
        // The fallback preserves symlink/canonical-path correctness, while the common
        // case above avoids a filesystem canonicalization for every process every tick.
        self.active_paths
            .contains(&normalize_path_for_compare(executable))
    }

    fn save(&self) -> Result<(), String> {
        let directory = self
            .path
            .parent()
            .ok_or_else(|| "无效的网络封禁规则路径".to_string())?;
        fs::create_dir_all(directory).map_err(|error| format!("无法创建配置目录：{error}"))?;
        let content = serde_json::to_vec_pretty(&self.rules)
            .map_err(|error| format!("无法序列化网络封禁规则：{error}"))?;
        fs::write(&self.path, content).map_err(|error| format!("无法保存网络封禁规则：{error}"))
    }
}

pub fn verify_running_process(pid: u32, requested_executable: &str) -> Result<(), String> {
    if requested_executable.trim().is_empty() {
        return Err("系统没有返回该进程的可执行文件路径，无法创建应用级规则".to_string());
    }
    let mut system = System::new_all();
    system.refresh_all();
    let process = system
        .process(Pid::from_u32(pid))
        .ok_or_else(|| "该进程已经退出，请刷新后重试".to_string())?;
    let actual = process
        .exe()
        .ok_or_else(|| "当前权限无法读取该进程的可执行文件路径".to_string())?;
    let actual = actual.to_string_lossy();
    if !paths_equal(&actual, requested_executable) {
        return Err("进程已发生变化，已拒绝为不匹配的可执行文件创建规则".to_string());
    }
    Ok(())
}

fn normalize_path(path: &str) -> Result<String, String> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err("必须使用可执行文件的绝对路径创建网络规则".to_string());
    }
    if !path.exists() {
        return Err("可执行文件已经不存在，无法创建网络规则".to_string());
    }
    Ok(normalize_path_for_compare(path.to_string_lossy().as_ref()))
}

fn normalize_path_for_compare(path: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        return path
            .strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('/', "\\")
            .to_lowercase();
    }
    #[cfg(not(target_os = "windows"))]
    let canonical = fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .to_string_lossy()
        .into_owned();
    #[cfg(not(target_os = "windows"))]
    canonical
}

fn raw_path_key(path: &str) -> String {
    #[cfg(target_os = "windows")]
    {
        return path
            .strip_prefix(r"\\?\")
            .unwrap_or(path)
            .replace('/', "\\")
            .to_lowercase();
    }
    #[cfg(not(target_os = "windows"))]
    path.to_string()
}

fn paths_equal(left: &str, right: &str) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

fn rule_id(executable: &str) -> String {
    let digest = Sha256::digest(executable.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(target_os = "windows")]
fn platform_block(executable: &str, identifier: &str, _pid: u32) -> Result<(), String> {
    windows::block(executable, identifier)
}
#[cfg(target_os = "windows")]
fn platform_unblock(_executable: &str, identifier: &str) -> Result<(), String> {
    windows::unblock(identifier)
}

#[cfg(target_os = "macos")]
fn platform_block(executable: &str, _identifier: &str, _pid: u32) -> Result<(), String> {
    macos::block(executable)
}
#[cfg(target_os = "macos")]
fn platform_unblock(executable: &str, _identifier: &str) -> Result<(), String> {
    macos::unblock(executable)
}

#[cfg(target_os = "linux")]
fn platform_block(executable: &str, identifier: &str, pid: u32) -> Result<(), String> {
    linux::block(executable, identifier, pid)
}
#[cfg(target_os = "linux")]
fn platform_unblock(_executable: &str, identifier: &str) -> Result<(), String> {
    linux::unblock(identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_ids_are_stable_and_short() {
        assert_eq!(rule_id("/bin/example"), rule_id("/bin/example"));
        assert_eq!(rule_id("/bin/example").len(), 16);
        assert_ne!(rule_id("/bin/example"), rule_id("/bin/other"));
    }
}
