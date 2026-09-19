use crate::models::{MonitorCoverage, PlatformProcessDetail, PlatformSample};
use std::path::Path;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as platform;

#[cfg(not(target_os = "macos"))]
mod portable;
#[cfg(not(target_os = "macos"))]
use portable as platform;

pub fn collect() -> PlatformSample {
    platform::collect()
}

pub fn coverage() -> MonitorCoverage {
    platform::coverage()
}

pub fn inspect_process(
    pid: u32,
    command_line: &[String],
    cwd: Option<&Path>,
) -> PlatformProcessDetail {
    platform::inspect_process(pid, command_line, cwd)
}
