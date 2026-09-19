mod collectors;
mod models;
mod monitor;
mod network_control;
mod tls_monitor;
mod upload_stats;

use models::{
    MonitorSettings, MonitorSnapshot, ProcessDetail, TlsInstallationInfo, TlsMonitorStatus,
};
use monitor::MonitorState;
use network_control::NetworkBlockManager;
use std::sync::Mutex;
use std::{fs, path::PathBuf};
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, State,
};
use upload_stats::{DailyUploadStatsResponse, UploadPointsResponse, UploadStatsStore};

struct AppState(Mutex<MonitorState>);
struct NetworkState(Mutex<NetworkBlockManager>);
struct UploadStatsState(Mutex<UploadStatsStore>);
struct TlsMonitorState(Mutex<tls_monitor::TlsMonitorManager>);

fn settings_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path()
        .app_config_dir()
        .ok()
        .map(|directory| directory.join("settings.json"))
}

fn load_settings(app: &tauri::AppHandle) -> Option<MonitorSettings> {
    let path = settings_path(app)?;
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_settings(app: &tauri::AppHandle, settings: &MonitorSettings) -> Result<(), String> {
    let path = settings_path(app).ok_or_else(|| "无法访问应用配置目录".to_string())?;
    if let Some(directory) = path.parent() {
        fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    }
    let content = serde_json::to_string_pretty(settings).map_err(|error| error.to_string())?;
    fs::write(path, content).map_err(|error| error.to_string())
}

fn upload_stats_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let directory = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问上传统计数据目录：{error}"))?;
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    Ok(directory.join("upload_stats.sqlite"))
}

#[tauri::command]
fn get_snapshot(
    state: State<'_, AppState>,
    network: State<'_, NetworkState>,
) -> Result<MonitorSnapshot, String> {
    let mut monitor = state.0.lock().map_err(|error| error.to_string())?;
    let mut snapshot = monitor.latest_snapshot();
    network
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .annotate_snapshot(&mut snapshot);
    Ok(snapshot)
}

#[tauri::command]
fn get_process_detail(
    pid: u32,
    process_instance_id: String,
    state: State<'_, AppState>,
) -> Result<ProcessDetail, String> {
    let mut monitor = state.0.lock().map_err(|error| error.to_string())?;
    monitor.process_detail(pid, &process_instance_id)
}

#[tauri::command]
fn get_tls_monitor_status(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsMonitorStatus, String> {
    let settings = state
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .settings
        .clone();
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    Ok(tls
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .status(&data_dir, &settings))
}

#[tauri::command]
fn start_tls_monitor(
    app: tauri::AppHandle,
    pid: u32,
    process_name: String,
    executable: String,
    state: State<'_, AppState>,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsMonitorStatus, String> {
    network_control::verify_running_process(pid, &executable)?;
    let settings = state
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .settings
        .clone();
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    tls.0
        .lock()
        .map_err(|error| error.to_string())?
        .start(&data_dir, &settings, pid, &process_name)
}

#[tauri::command]
fn stop_tls_monitor(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsMonitorStatus, String> {
    let settings = state
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .settings
        .clone();
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    let mut manager = tls.0.lock().map_err(|error| error.to_string())?;
    manager.stop_all();
    Ok(manager.status(&data_dir, &settings))
}

#[tauri::command]
fn stop_tls_process_monitor(
    app: tauri::AppHandle,
    pid: u32,
    state: State<'_, AppState>,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsMonitorStatus, String> {
    let settings = state
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .settings
        .clone();
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    let mut manager = tls.0.lock().map_err(|error| error.to_string())?;
    manager.stop(pid);
    Ok(manager.status(&data_dir, &settings))
}

#[tauri::command]
fn stop_all_tls_monitors(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsMonitorStatus, String> {
    let settings = state
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .settings
        .clone();
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    let mut manager = tls.0.lock().map_err(|error| error.to_string())?;
    manager.stop_all();
    Ok(manager.status(&data_dir, &settings))
}

#[tauri::command]
fn get_tls_installation_info(app: tauri::AppHandle) -> Result<TlsInstallationInfo, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    Ok(tls_monitor::installation_info(&data_dir))
}

#[tauri::command]
fn install_tls_engine(app: tauri::AppHandle) -> Result<TlsInstallationInfo, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    tls_monitor::install_engine(&data_dir)
}

#[tauri::command]
fn uninstall_tls_engine(
    app: tauri::AppHandle,
    tls: State<'_, TlsMonitorState>,
) -> Result<TlsInstallationInfo, String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("无法访问 TLS 监控数据目录：{error}"))?;
    let running = tls
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .is_running();
    tls_monitor::uninstall_engine(&data_dir, running)
}

#[tauri::command]
fn toggle_monitoring(
    state: State<'_, AppState>,
    network: State<'_, NetworkState>,
) -> Result<MonitorSnapshot, String> {
    let mut monitor = state.0.lock().map_err(|error| error.to_string())?;
    monitor.monitoring = !monitor.monitoring;
    let mut snapshot = monitor.snapshot();
    network
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .annotate_snapshot(&mut snapshot);
    Ok(snapshot)
}

#[tauri::command]
fn update_settings(
    app: tauri::AppHandle,
    settings: MonitorSettings,
    state: State<'_, AppState>,
    network: State<'_, NetworkState>,
) -> Result<MonitorSnapshot, String> {
    let mut monitor = state.0.lock().map_err(|error| error.to_string())?;
    monitor.settings = settings.clone();
    save_settings(&app, &settings)?;
    let mut snapshot = monitor.snapshot();
    network
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .annotate_snapshot(&mut snapshot);
    Ok(snapshot)
}

#[tauri::command]
fn block_process_network(
    pid: u32,
    executable: String,
    process_name: String,
    network: State<'_, NetworkState>,
) -> Result<(), String> {
    network_control::verify_running_process(pid, &executable)?;
    network
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .block(&executable, &process_name, pid)
}

#[tauri::command]
fn unblock_process_network(
    executable: String,
    network: State<'_, NetworkState>,
) -> Result<(), String> {
    network
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .unblock(&executable)
}

#[tauri::command]
fn get_daily_upload_stats(
    program_id: String,
    start_date: Option<String>,
    end_date: Option<String>,
    stats: State<'_, UploadStatsState>,
) -> Result<DailyUploadStatsResponse, String> {
    stats.0.lock().map_err(|error| error.to_string())?.daily(
        &program_id,
        start_date.as_deref(),
        end_date.as_deref(),
    )
}

#[tauri::command]
fn get_upload_stats_points(
    program_id: String,
    date: String,
    hour: Option<u8>,
    stats: State<'_, UploadStatsState>,
) -> Result<UploadPointsResponse, String> {
    stats
        .0
        .lock()
        .map_err(|error| error.to_string())?
        .points(&program_id, &date, hour)
}

fn tray_pixels() -> Vec<u8> {
    let mut pixels = vec![0_u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let dx = x as f32 - 15.5;
            let dy = y as f32 - 15.5;
            let distance = (dx * dx + dy * dy).sqrt();
            let index = (y * 32 + x) * 4;
            if distance <= 13.0 {
                let inner = distance <= 8.0 || (dx.abs() <= 2.0 && dy.abs() <= 11.0);
                pixels[index] = if inner { 255 } else { 239 };
                pixels[index + 1] = if inner { 255 } else { 107 };
                pixels[index + 2] = if inner { 255 } else { 91 };
                pixels[index + 3] = 255;
            }
        }
    }
    pixels
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState(Mutex::new(MonitorState::default())))
        .manage(TlsMonitorState(Mutex::new(
            tls_monitor::TlsMonitorManager::default(),
        )))
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_process_detail,
            get_tls_monitor_status,
            start_tls_monitor,
            stop_tls_monitor,
            stop_tls_process_monitor,
            stop_all_tls_monitors,
            get_tls_installation_info,
            install_tls_engine,
            uninstall_tls_engine,
            toggle_monitoring,
            update_settings,
            block_process_network,
            unblock_process_network,
            get_daily_upload_stats,
            get_upload_stats_points
        ])
        .setup(|app| {
            let network = NetworkBlockManager::load(app.handle())?;
            app.manage(NetworkState(Mutex::new(network)));
            let stats = UploadStatsStore::open(&upload_stats_path(app.handle())?)
                .map_err(|error| format!("无法初始化上传统计数据库：{error}"))?;
            app.manage(UploadStatsState(Mutex::new(stats)));
            if let Some(settings) = load_settings(app.handle()) {
                if let Ok(mut monitor) = app.state::<AppState>().0.lock() {
                    monitor.settings = settings;
                }
            }
            let monitor_app = app.handle().clone();
            std::thread::spawn(move || loop {
                let state = monitor_app.state::<AppState>();
                if let Ok(mut monitor) = state.0.lock() {
                    if monitor.monitoring {
                        let snapshot = monitor.snapshot();
                        drop(monitor);
                        if let Ok(mut stats) = monitor_app.state::<UploadStatsState>().0.lock() {
                            if let Err(error) = stats.record_snapshot(&snapshot) {
                                eprintln!("上传统计写入失败：{error}");
                            }
                        }
                    }
                }
                // Process metrics stay responsive, while expensive platform network
                // collectors are independently throttled inside MonitorState.
                std::thread::sleep(std::time::Duration::from_millis(700));
            });
            let open = MenuItem::with_id(app, "open", "打开 Sentinel Flow", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let tray = TrayIconBuilder::new()
                .tooltip("Sentinel Flow · 本地流量监控")
                .icon(Image::new_owned(tray_pixels(), 32, 32))
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;
            app.manage(tray);
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Sentinel Flow");
}
