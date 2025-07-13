use crate::{error::Result, types::Config};
use std::fs;
use std::path::{Path, PathBuf};

/// Configuration file search paths in order of precedence
pub fn get_config_search_paths(executable_path: &Path, config_arg: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    
    // 1. Command line argument
    if let Some(config_path) = config_arg {
        paths.push(PathBuf::from(config_path));
    }
    
    // 2. Executable directory
    if let Some(parent) = executable_path.parent() {
        paths.push(parent.join("graftcp-local.conf"));
    }
    
    // 3. XDG_CONFIG_HOME or ~/.config
    if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        paths.push(PathBuf::from(xdg_config).join("graftcp-local/graftcp-local.conf"));
    } else if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(home).join(".config/graftcp-local/graftcp-local.conf"));
    }
    
    // 4. System-wide config
    paths.push(PathBuf::from("/etc/graftcp-local/graftcp-local.conf"));
    
    paths
}

/// Load configuration from file, falling back to defaults
pub fn load_config(executable_path: &Path, config_arg: Option<&str>) -> Result<Config> {
    let search_paths = get_config_search_paths(executable_path, config_arg);
    
    for path in search_paths {
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            let config: Config = toml::from_str(&content)
                .map_err(|e| crate::error::GraftcpError::ConfigError(
                    format!("Failed to parse config file {}: {}", path.display(), e)
                ))?;
            return Ok(config);
        }
    }
    
    // Return default config if no file found
    Ok(Config::default())
}