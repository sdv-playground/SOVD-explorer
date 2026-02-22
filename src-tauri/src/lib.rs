use serde::{Deserialize, Serialize};
use sovd_uds::uds::standard_did;
use sovd_client::{
    AppInfo, Component, DataResponse, FaultInfo, OperationInfo, OperationResponse,
    ParameterInfo, SecurityLevel, SovdClient,
    FlashClient,
};
use std::sync::Mutex;
use std::collections::HashMap;
use tauri::State;

// =============================================================================
// State Management
// =============================================================================

struct AppState {
    client: Mutex<Option<SovdClient>>,
    server_url: Mutex<String>,
    flash_client: Mutex<Option<FlashClient>>,
    current_flash_component: Mutex<Option<String>>,
    helper_url: Mutex<Option<String>>,
    helper_token: Mutex<Option<String>>,
    http_client: reqwest::Client,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            client: Mutex::new(None),
            server_url: Mutex::new("http://localhost:4000".to_string()),
            flash_client: Mutex::new(None),
            current_flash_component: Mutex::new(None),
            helper_url: Mutex::new(None),
            helper_token: Mutex::new(None),
            http_client: reqwest::Client::new(),
        }
    }
}

/// Helper to get a cloned client (SovdClient is Clone)
fn get_client(state: &State<'_, AppState>) -> Result<SovdClient, String> {
    state
        .client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Not connected".to_string())
}

// =============================================================================
// Response Types for Frontend
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub server_url: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub id: String,
    pub value: String,
    pub seed: Option<String>,
}

// =============================================================================
// Connection Commands
// =============================================================================

#[tauri::command]
async fn connect(state: State<'_, AppState>, server_url: String) -> Result<ConnectionStatus, String> {
    match SovdClient::new(&server_url) {
        Ok(client) => {
            // Test the connection with a health check
            match client.health().await {
                Ok(_) => {
                    *state.client.lock().unwrap() = Some(client);
                    *state.server_url.lock().unwrap() = server_url.clone();
                    Ok(ConnectionStatus {
                        connected: true,
                        server_url,
                        error: None,
                    })
                }
                Err(e) => Ok(ConnectionStatus {
                    connected: false,
                    server_url,
                    error: Some(format!("Health check failed: {}", e)),
                }),
            }
        }
        Err(e) => Ok(ConnectionStatus {
            connected: false,
            server_url,
            error: Some(format!("Failed to create client: {}", e)),
        }),
    }
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    *state.client.lock().unwrap() = None;
    Ok(())
}

#[tauri::command]
async fn get_connection_status(state: State<'_, AppState>) -> Result<ConnectionStatus, String> {
    let has_client = state.client.lock().unwrap().is_some();
    let server_url = state.server_url.lock().unwrap().clone();

    Ok(ConnectionStatus {
        connected: has_client,
        server_url,
        error: None,
    })
}

// =============================================================================
// Component Commands
// =============================================================================

#[tauri::command]
async fn list_components(state: State<'_, AppState>) -> Result<Vec<Component>, String> {
    let client = get_client(&state)?;
    client
        .list_components()
        .await
        .map_err(|e| format!("Failed to list components: {}", e))
}

#[tauri::command]
async fn get_component(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<Component, String> {
    let client = get_client(&state)?;
    client
        .get_component(&component_id)
        .await
        .map_err(|e| format!("Failed to get component: {}", e))
}

#[tauri::command]
async fn list_apps(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<Vec<AppInfo>, String> {
    let client = get_client(&state)?;
    client
        .list_apps(&component_id)
        .await
        .map_err(|e| format!("Failed to list apps: {}", e))
}

#[tauri::command]
async fn list_sub_entity_apps(
    state: State<'_, AppState>,
    component_id: String,
    app_id: String,
) -> Result<Vec<AppInfo>, String> {
    let client = get_client(&state)?;
    client
        .list_sub_entity_apps(&component_id, &app_id)
        .await
        .map_err(|e| format!("Failed to list sub-entity apps: {}", e))
}

#[tauri::command]
async fn get_app_detail(
    state: State<'_, AppState>,
    component_id: String,
    app_id: String,
) -> Result<AppInfo, String> {
    let client = get_client(&state)?;
    client
        .get_app(&component_id, &app_id)
        .await
        .map_err(|e| format!("Failed to get app detail: {}", e))
}

// =============================================================================
// Data/Parameter Commands
// =============================================================================

#[tauri::command]
async fn list_parameters(
    state: State<'_, AppState>,
    component_id: String,
    app_path: Option<String>,
) -> Result<Vec<ParameterInfo>, String> {
    let client = get_client(&state)?;
    let result = if let Some(ref path) = app_path {
        client.list_sub_entity_parameters(&component_id, path).await
    } else {
        client.list_parameters(&component_id).await
    };
    result
        .map(|r| r.items)
        .map_err(|e| format!("Failed to list parameters: {}", e))
}

#[tauri::command]
async fn read_parameter(
    state: State<'_, AppState>,
    component_id: String,
    parameter_id: String,
    app_path: Option<String>,
) -> Result<DataResponse, String> {
    let client = get_client(&state)?;
    let result = if let Some(ref path) = app_path {
        client
            .read_sub_entity_data(&component_id, path, &parameter_id)
            .await
    } else {
        client.read_data(&component_id, &parameter_id).await
    };
    result.map_err(|e| format!("Failed to read parameter: {}", e))
}

#[tauri::command]
async fn read_parameter_raw(
    state: State<'_, AppState>,
    component_id: String,
    parameter_id: String,
    app_path: Option<String>,
) -> Result<DataResponse, String> {
    let client = get_client(&state)?;
    let result = if let Some(ref path) = app_path {
        client
            .read_sub_entity_data_raw(&component_id, path, &parameter_id)
            .await
    } else {
        client.read_data_raw(&component_id, &parameter_id).await
    };
    result.map_err(|e| format!("Failed to read raw parameter: {}", e))
}

// Feature 1: Write Parameters
#[tauri::command]
async fn write_parameter(
    state: State<'_, AppState>,
    component_id: String,
    data_id: String,
    value: serde_json::Value,
    app_path: Option<String>,
) -> Result<(), String> {
    let client = get_client(&state)?;
    let result = if let Some(ref path) = app_path {
        client
            .write_sub_entity_data(&component_id, path, &data_id, value)
            .await
    } else {
        client.write_data(&component_id, &data_id, value).await
    };
    result.map_err(|e| format!("Failed to write parameter: {}", e))
}

// Feature 6: ECU Info - Read standard identification DIDs
#[tauri::command]
async fn get_ecu_info(
    state: State<'_, AppState>,
    component_id: String,
    prefix: Option<String>,
) -> Result<HashMap<String, String>, String> {
    let client = get_client(&state)?;
    let mut info = HashMap::new();

    // Read all standard identification DIDs
    // When prefix is set, use sub-entity route (e.g., /apps/engine_ecu/data/F190)
    for &(did, key, _label) in standard_did::IDENTIFICATION_DIDS {
        let did_str = format!("F{:03X}", did & 0xFFF);
        let result = if let Some(ref path) = prefix {
            client.read_sub_entity_data(&component_id, path, &did_str).await
        } else {
            client.read_data(&component_id, &did_str).await
        };
        if let Ok(data) = result {
            if let Some(val) = data.value.as_str() {
                info.insert(key.to_string(), val.to_string());
            } else if let Some(val) = data.value.as_i64() {
                info.insert(key.to_string(), val.to_string());
            } else if !data.value.is_null() {
                info.insert(key.to_string(), data.value.to_string());
            }
        }
    }

    // Also try to read named parameters that might exist
    // (fallback for servers that expose by semantic name instead of DID)
    let named_params = [
        ("vin", "vin"),
        ("ecu_serial", "ecu_serial"),
        ("ecu_sw_version", "ecu_sw_version"),
        ("hw_version", "hw_version"),
        ("hw_number", "hw_number"),
        ("sw_number", "sw_number"),
        ("part_number", "part_number"),
        ("supplier", "supplier"),
        ("supplier_sw_version", "supplier_sw_version"),
        ("system_name", "system_name"),
        ("mfg_date", "mfg_date"),
        ("programming_date", "programming_date"),
    ];

    for (key, param) in &named_params {
        if !info.contains_key(*key) {
            let result = if let Some(ref path) = prefix {
                client.read_sub_entity_data(&component_id, path, param).await
            } else {
                client.read_data(&component_id, param).await
            };
            if let Ok(data) = result {
                if let Some(val) = data.value.as_str() {
                    info.insert(key.to_string(), val.to_string());
                } else if let Some(val) = data.value.as_i64() {
                    info.insert(key.to_string(), val.to_string());
                } else if !data.value.is_null() {
                    info.insert(key.to_string(), data.value.to_string());
                }
            }
        }
    }

    Ok(info)
}

// Feature 2: I/O Control (uses outputs API)
#[derive(Debug, Serialize, Deserialize)]
pub struct IoControlInfo {
    pub id: String,
    pub name: String,
    pub current_state: Option<String>,
    pub value: Option<serde_json::Value>,
    pub default_value: Option<serde_json::Value>,
    pub allowed: Option<Vec<serde_json::Value>>,
    pub controllable: bool,
    pub controlled_by_tester: Option<bool>,
    pub frozen: Option<bool>,
    pub requires_security: Option<bool>,
    pub security_level: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IoControlResponse {
    pub success: bool,
    pub state: String,
    pub message: Option<String>,
    pub frozen: Option<bool>,
    pub new_value: Option<String>,
    pub value: Option<serde_json::Value>,
}

#[tauri::command]
async fn list_io_controls(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<Vec<IoControlInfo>, String> {
    let client = get_client(&state)?;

    // Get the list of outputs (metadata only)
    let outputs = client
        .list_outputs(&component_id)
        .await
        .map_err(|e| format!("I/O Control not supported: {}", e))?;

    // Fetch detail for each output to get current state, allowed values, etc.
    let mut controls = Vec::new();
    for o in &outputs {
        let detail = client.get_output(&component_id, &o.id).await.ok();
        let (name, current_state, value, default_value, allowed, controlled_by_tester, frozen, requires_security, security_level) =
            if let Some(ref d) = detail {
                (
                    d.name.clone().unwrap_or_else(|| o.name.clone().unwrap_or_else(|| o.id.clone())),
                    d.current_value.clone(),
                    d.value.clone(),
                    d.default.clone(),
                    d.allowed.clone(),
                    d.controlled_by_tester,
                    d.frozen,
                    d.requires_security,
                    d.security_level,
                )
            } else {
                (
                    o.name.clone().unwrap_or_else(|| o.id.clone()),
                    None, None, None, None, None, None, None, o.security_level,
                )
            };

        controls.push(IoControlInfo {
            id: o.id.clone(),
            name,
            current_state,
            value,
            default_value,
            allowed,
            controllable: true,
            controlled_by_tester,
            frozen,
            requires_security,
            security_level,
        });
    }

    Ok(controls)
}

#[tauri::command]
async fn io_control(
    state: State<'_, AppState>,
    component_id: String,
    data_id: String,
    action: String,
    value: Option<serde_json::Value>,
) -> Result<IoControlResponse, String> {
    let client = get_client(&state)?;

    // Map action names to SOVD output control actions
    let sovd_action = match action.as_str() {
        "reset_to_default" => "reset_to_default",
        "freeze_current" => "freeze",
        "short_term_adjust" => "short_term_adjust",
        _ => return Err(format!("Unknown I/O control action: {}", action)),
    };

    match client.control_output(&component_id, &data_id, sovd_action, value).await {
        Ok(response) => Ok(IoControlResponse {
            success: response.success,
            state: if response.controlled_by_tester { "controlled" } else { "released" }.to_string(),
            message: response.error,
            frozen: Some(response.frozen),
            new_value: response.new_value,
            value: response.value,
        }),
        Err(e) => Ok(IoControlResponse {
            success: false,
            state: "error".to_string(),
            message: Some(format!("{}", e)),
            frozen: None,
            new_value: None,
            value: None,
        }),
    }
}

// Feature 8: Export Logs
#[derive(Debug, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub component: String,
    pub action: String,
    pub details: String,
    pub success: bool,
}

#[tauri::command]
async fn export_logs(logs: Vec<LogEntry>, format: String) -> Result<(), String> {
    use std::io::Write;

    // Generate filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let extension = match format.as_str() {
        "json" => "json",
        "csv" => "csv",
        "txt" => "txt",
        _ => return Err(format!("Unknown format: {}", format)),
    };

    let filename = format!("sovd_log_{}_{}", timestamp, extension);

    // Use native file dialog via rfd
    let path = rfd::FileDialog::new()
        .set_file_name(&filename)
        .add_filter("Log files", &[extension])
        .save_file();

    let path = match path {
        Some(p) => p,
        None => return Ok(()), // User cancelled
    };

    let content = match format.as_str() {
        "json" => serde_json::to_string_pretty(&logs)
            .map_err(|e| format!("Failed to serialize logs: {}", e))?,
        "csv" => {
            let mut csv = String::from("timestamp,type,component,action,details,success\n");
            for log in &logs {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    log.timestamp,
                    log.log_type,
                    log.component,
                    log.action,
                    log.details.replace(',', ";"),
                    log.success
                ));
            }
            csv
        }
        "txt" => {
            let mut txt = String::new();
            for log in &logs {
                txt.push_str(&format!(
                    "[{}] {} | {} | {} | {} | {}\n",
                    log.timestamp,
                    log.log_type.to_uppercase(),
                    log.component,
                    log.action,
                    log.details,
                    if log.success { "OK" } else { "FAIL" }
                ));
            }
            txt
        }
        _ => return Err(format!("Unknown format: {}", format)),
    };

    let mut file = std::fs::File::create(&path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(())
}

// =============================================================================
// Fault Commands
// =============================================================================

#[tauri::command]
async fn list_faults(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<Vec<FaultInfo>, String> {
    let client = get_client(&state)?;
    client
        .get_faults(&component_id)
        .await
        .map_err(|e| format!("Failed to list faults: {}", e))
}

#[tauri::command]
async fn clear_faults(state: State<'_, AppState>, component_id: String) -> Result<bool, String> {
    let client = get_client(&state)?;
    client
        .clear_faults(&component_id)
        .await
        .map(|r| r.success)
        .map_err(|e| format!("Failed to clear faults: {}", e))
}

// =============================================================================
// Operation Commands
// =============================================================================

#[tauri::command]
async fn list_operations(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<Vec<OperationInfo>, String> {
    let client = get_client(&state)?;
    client
        .list_operations(&component_id)
        .await
        .map_err(|e| format!("Failed to list operations: {}", e))
}

#[tauri::command]
async fn execute_operation(
    state: State<'_, AppState>,
    component_id: String,
    operation_id: String,
    action: String,
) -> Result<OperationResponse, String> {
    let client = get_client(&state)?;
    client
        .execute_operation(&component_id, &operation_id, &action, None)
        .await
        .map_err(|e| format!("Failed to execute operation: {}", e))
}

// =============================================================================
// Session/Mode Commands
// =============================================================================

#[tauri::command]
async fn get_session(
    state: State<'_, AppState>,
    component_id: String,
    target: Option<String>,
) -> Result<SessionInfo, String> {
    let client = get_client(&state)?;
    let mode = client
        .get_mode_targeted(&component_id, "session", target.as_deref())
        .await
        .map_err(|e| format!("Failed to get session: {}", e))?;

    Ok(SessionInfo {
        id: mode.id,
        value: mode
            .value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string()),
    })
}

#[tauri::command]
async fn set_session(
    state: State<'_, AppState>,
    component_id: String,
    session: String,
    target: Option<String>,
) -> Result<SessionInfo, String> {
    let client = get_client(&state)?;

    let body = serde_json::json!({ "value": session });
    client
        .set_mode_targeted(&component_id, "session", body, target.as_deref())
        .await
        .map_err(|e| format!("Failed to set session: {}", e))?;

    // Fetch the updated session state
    let mode = client
        .get_mode_targeted(&component_id, "session", target.as_deref())
        .await
        .map_err(|e| format!("Failed to get updated session: {}", e))?;

    Ok(SessionInfo {
        id: mode.id,
        value: mode
            .value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| session),
    })
}

#[tauri::command]
async fn get_security(
    state: State<'_, AppState>,
    component_id: String,
    target: Option<String>,
) -> Result<SecurityInfo, String> {
    let client = get_client(&state)?;
    let mode = client
        .get_mode_targeted(&component_id, "security", target.as_deref())
        .await
        .map_err(|e| format!("Failed to get security: {}", e))?;

    let seed_str = mode.seed.as_ref().and_then(|s| {
        s.as_object()
            .and_then(|o| o.get("Request_Seed"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    Ok(SecurityInfo {
        id: mode.id,
        value: mode
            .value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "locked".to_string()),
        seed: seed_str,
    })
}

#[tauri::command]
async fn request_security_seed(
    state: State<'_, AppState>,
    component_id: String,
    level: u8,
    target: Option<String>,
) -> Result<SecurityInfo, String> {
    let client = get_client(&state)?;
    let security_level = SecurityLevel(level);
    let seed_bytes = client
        .security_access_request_seed_targeted(&component_id, security_level, target.as_deref())
        .await
        .map_err(|e| format!("Failed to request seed: {}", e))?;

    // Convert seed bytes to hex string
    let seed_hex = seed_bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ");

    Ok(SecurityInfo {
        id: "security".to_string(),
        value: format!("level{}_seedavailable", security_level.as_level_number()),
        seed: Some(seed_hex),
    })
}

#[tauri::command]
async fn send_security_key(
    state: State<'_, AppState>,
    component_id: String,
    level: u8,
    key: String,
    target: Option<String>,
) -> Result<SecurityInfo, String> {
    let client = get_client(&state)?;
    let security_level = SecurityLevel(level);

    // Parse hex key string
    let key_bytes = hex::decode(&key)
        .map_err(|e| format!("Invalid hex key: {}", e))?;

    client
        .security_access_send_key_targeted(&component_id, security_level, &key_bytes, target.as_deref())
        .await
        .map_err(|e| format!("Failed to send key: {}", e))?;

    Ok(SecurityInfo {
        id: "security".to_string(),
        value: format!("level{}", security_level.as_level_number()),
        seed: None,
    })
}

// =============================================================================
// Software Update / Flash Commands
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct FlashProgress {
    pub phase: String,
    pub percent: Option<f64>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivationInfo {
    pub supports_rollback: bool,
    pub state: String,
    pub active_version: Option<String>,
    pub previous_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitRollbackResult {
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadResult {
    pub upload_id: String,
    pub file_id: Option<String>,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlashResult {
    pub transfer_id: String,
    pub state: String,
    pub blocks_transferred: u32,
    pub blocks_total: u32,
    pub percent: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferInfo {
    pub transfer_id: String,
    pub state: String,
    pub error: Option<String>,
}

#[tauri::command]
async fn flash_list_transfers(
    state: State<'_, AppState>,
) -> Result<Vec<TransferInfo>, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized. Call flash_init first.".to_string())?;

    let response = flash_client
        .list_transfers()
        .await
        .map_err(|e| format!("Failed to list transfers: {}", e))?;

    Ok(response
        .transfers
        .into_iter()
        .map(|t| TransferInfo {
            transfer_id: t.transfer_id,
            state: format!("{:?}", t.state).to_lowercase(),
            error: t.error.map(|e| e.message),
        })
        .collect())
}

#[tauri::command]
async fn flash_init(
    state: State<'_, AppState>,
    component_id: String,
    gateway_id: Option<String>,
) -> Result<bool, String> {
    let server_url = state.server_url.lock().unwrap().clone();

    let flash_client = if let Some(ref gw) = gateway_id {
        FlashClient::for_sovd_sub_entity(&server_url, gw, &component_id)
    } else {
        FlashClient::for_sovd(&server_url, &component_id)
    }.map_err(|e| format!("Failed to create flash client: {}", e))?;

    *state.flash_client.lock().unwrap() = Some(flash_client);
    *state.current_flash_component.lock().unwrap() = Some(component_id);

    Ok(true)
}

#[tauri::command]
async fn flash_upload(
    state: State<'_, AppState>,
    data: Vec<u8>,
    filename: Option<String>,
) -> Result<UploadResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized. Call flash_init first.".to_string())?;

    let upload = if let Some(name) = filename {
        flash_client.upload_file_with_name(&data, Some(&name)).await
    } else {
        flash_client.upload_file(&data).await
    }.map_err(|e| format!("Upload failed: {}", e))?;

    Ok(UploadResult {
        upload_id: upload.upload_id.clone(),
        file_id: None, // file_id is available after polling
        state: "uploading".to_string(),
    })
}

#[tauri::command]
async fn flash_upload_from_path(
    state: State<'_, AppState>,
    path: String,
) -> Result<UploadResult, String> {
    // Read file from path
    let data = std::fs::read(&path)
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

    // Extract filename from path
    let filename = std::path::Path::new(&path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized. Call flash_init first.".to_string())?;

    let upload = if let Some(name) = filename {
        flash_client.upload_file_with_name(&data, Some(&name)).await
    } else {
        flash_client.upload_file(&data).await
    }.map_err(|e| format!("Upload failed: {}", e))?;

    Ok(UploadResult {
        upload_id: upload.upload_id.clone(),
        file_id: None,
        state: "uploading".to_string(),
    })
}

#[tauri::command]
async fn flash_poll_upload(
    state: State<'_, AppState>,
    upload_id: String,
) -> Result<UploadResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let status = flash_client
        .get_upload_status(&upload_id)
        .await
        .map_err(|e| format!("Failed to get upload status: {}", e))?;

    Ok(UploadResult {
        upload_id,
        file_id: status.file_id,
        state: format!("{:?}", status.state).to_lowercase(),
    })
}

#[tauri::command]
async fn flash_verify(
    state: State<'_, AppState>,
    file_id: String,
) -> Result<bool, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    flash_client
        .verify_file(&file_id)
        .await
        .map_err(|e| format!("Verification failed: {}", e))?;

    Ok(true)
}

#[tauri::command]
async fn flash_start(
    state: State<'_, AppState>,
    file_id: String,
) -> Result<FlashResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let response = flash_client
        .start_flash(&file_id)
        .await
        .map_err(|e| format!("Failed to start flash: {}", e))?;

    Ok(FlashResult {
        transfer_id: response.transfer_id,
        state: "flashing".to_string(),
        blocks_transferred: 0,
        blocks_total: 0,
        percent: Some(0.0),
        error: None,
    })
}

#[tauri::command]
async fn flash_poll_progress(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<FlashResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let status = flash_client
        .get_flash_status(&transfer_id)
        .await
        .map_err(|e| format!("Failed to get flash status: {}", e))?;

    let (blocks_transferred, blocks_total, percent) = status
        .progress
        .map(|p| (p.blocks_transferred, p.blocks_total, p.percent))
        .unwrap_or((0, 0, None));

    Ok(FlashResult {
        transfer_id,
        state: format!("{:?}", status.state).to_lowercase(),
        blocks_transferred,
        blocks_total,
        percent,
        error: status.error.map(|e| e.message),
    })
}

#[tauri::command]
async fn flash_abort(
    state: State<'_, AppState>,
    transfer_id: String,
) -> Result<bool, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    flash_client
        .abort_flash(&transfer_id)
        .await
        .map_err(|e| format!("Failed to abort flash: {}", e))?;

    Ok(true)
}

#[tauri::command]
async fn flash_finalize(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    flash_client
        .transfer_exit()
        .await
        .map_err(|e| format!("Transfer exit failed: {}", e))?;

    Ok(true)
}

#[tauri::command]
async fn flash_reset_ecu(
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    flash_client
        .ecu_reset()
        .await
        .map_err(|e| format!("ECU reset failed: {}", e))?;

    Ok(true)
}

#[tauri::command]
async fn flash_commit(
    state: State<'_, AppState>,
) -> Result<CommitRollbackResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let response = flash_client
        .commit_flash()
        .await
        .map_err(|e| format!("Commit failed: {}", e))?;

    // Clear flash client state after commit
    *state.flash_client.lock().unwrap() = None;
    *state.current_flash_component.lock().unwrap() = None;

    Ok(CommitRollbackResult {
        success: response.success,
        message: response.message,
    })
}

#[tauri::command]
async fn flash_rollback(
    state: State<'_, AppState>,
) -> Result<CommitRollbackResult, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let response = flash_client
        .rollback_flash()
        .await
        .map_err(|e| format!("Rollback failed: {}", e))?;

    // Clear flash client state after rollback
    *state.flash_client.lock().unwrap() = None;
    *state.current_flash_component.lock().unwrap() = None;

    Ok(CommitRollbackResult {
        success: response.success,
        message: response.message,
    })
}

#[tauri::command]
async fn flash_get_activation(
    state: State<'_, AppState>,
) -> Result<ActivationInfo, String> {
    let flash_client = state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized".to_string())?;

    let response = flash_client
        .get_activation_state()
        .await
        .map_err(|e| format!("Failed to get activation state: {}", e))?;

    Ok(ActivationInfo {
        supports_rollback: response.supports_rollback,
        state: response.state,
        active_version: response.active_version,
        previous_version: response.previous_version,
    })
}

// =============================================================================
// Security Helper Commands
// =============================================================================

#[derive(Debug, Serialize, Deserialize)]
struct HelperProviderInfo {
    name: String,
    issuer: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HelperInfo {
    name: String,
    version: String,
    auth_mode: String,
    #[serde(default)]
    providers: Option<Vec<HelperProviderInfo>>,
    supported_ecus: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HelperResult {
    success: bool,
    key: Option<String>,
    error: Option<String>,
}

#[tauri::command]
async fn set_security_helper(
    state: State<'_, AppState>,
    url: String,
    token: String,
) -> Result<(), String> {
    *state.helper_url.lock().unwrap() = Some(url);
    *state.helper_token.lock().unwrap() = Some(token);
    Ok(())
}

#[tauri::command]
async fn security_helper_info(state: State<'_, AppState>) -> Result<HelperInfo, String> {
    let url = state
        .helper_url
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Security helper not configured".to_string())?;

    let resp = state
        .http_client
        .get(format!("{}/info", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| format!("Failed to reach helper: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("Helper returned status {}", resp.status()));
    }

    resp.json::<HelperInfo>()
        .await
        .map_err(|e| format!("Invalid helper response: {}", e))
}

#[tauri::command]
async fn security_helper_calculate(
    state: State<'_, AppState>,
    seed: String,
    level: u8,
    component_id: String,
    vin: Option<String>,
    logical_address: Option<String>,
    part_number: Option<String>,
    hw_version: Option<String>,
    sw_version: Option<String>,
    supplier: Option<String>,
) -> Result<HelperResult, String> {
    let url = state
        .helper_url
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Security helper not configured".to_string())?;

    let token = state
        .helper_token
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Security helper token not set".to_string())?;

    let body = serde_json::json!({
        "seed": seed,
        "level": level,
        "vehicle": { "vin": vin },
        "ecu": {
            "component_id": component_id,
            "logical_address": logical_address,
            "part_number": part_number,
            "hw_version": hw_version,
            "sw_version": sw_version,
            "supplier": supplier,
        },
    });

    let resp = state
        .http_client
        .post(format!("{}/calculate", url.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {}", token))
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Failed to reach helper: {}", e))?;

    resp.json::<HelperResult>()
        .await
        .map_err(|e| format!("Invalid helper response: {}", e))
}

// =============================================================================
// OIDC Login Flow
// =============================================================================

#[derive(Debug, Deserialize)]
struct OidcDiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OidcLoginResult {
    token: String,
    email: Option<String>,
    name: Option<String>,
    provider: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    #[allow(dead_code)]
    sub: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_jwt_claims_unverified(jwt: &str) -> Result<IdTokenClaims, String> {
    use base64::Engine;
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT: expected 3 parts".to_string());
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| format!("Failed to decode JWT payload: {}", e))?;
    serde_json::from_slice(&payload)
        .map_err(|e| format!("Failed to parse JWT claims: {}", e))
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[tauri::command]
async fn oidc_login(
    state: State<'_, AppState>,
    provider_name: String,
) -> Result<OidcLoginResult, String> {
    // 1. Fetch /info from helper to get provider details
    let url = state
        .helper_url
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Security helper not configured".to_string())?;

    let info = state
        .http_client
        .get(format!("{}/info", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| format!("Failed to reach helper: {}", e))?
        .json::<HelperInfo>()
        .await
        .map_err(|e| format!("Invalid helper response: {}", e))?;

    let provider = info
        .providers
        .as_ref()
        .and_then(|ps| ps.iter().find(|p| p.name == provider_name))
        .ok_or_else(|| format!("Provider '{}' not found in helper /info", provider_name))?;

    let client_id = provider
        .client_id
        .clone()
        .ok_or_else(|| format!("Provider '{}' did not expose client_id", provider_name))?;
    let client_secret = provider.client_secret.clone();
    let issuer = provider.issuer.clone();

    // 2. Fetch OIDC discovery document
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery: OidcDiscoveryDoc = state
        .http_client
        .get(&discovery_url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch OIDC discovery: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse OIDC discovery: {}", e))?;

    // 3. Generate PKCE code_verifier and code_challenge (S256)
    use sha2::Digest;
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64_url_encode(&verifier_bytes);
    let challenge_hash = sha2::Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64_url_encode(&challenge_hash);

    // 4. Generate random state nonce
    let state_bytes: [u8; 16] = rand::random();
    let state_nonce = hex::encode(state_bytes);

    // 5. Bind temporary localhost callback server (OS picks free port)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback listener: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get listener address: {}", e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

    // 6. Construct authorization URL
    let auth_url = format!(
        "{}?{}",
        discovery.authorization_endpoint,
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state_nonce)
            .finish()
    );

    // 7. Open browser
    open::that(&auth_url).map_err(|e| format!("Failed to open browser: {}", e))?;

    // 8. Wait for callback (with 120s timeout)
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(String, String), String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        use axum::{extract::Query, response::Html, routing::get as axum_get, Router as AxumRouter};

        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));
        let app = AxumRouter::new().route(
            "/callback",
            axum_get(move |Query(params): Query<CallbackParams>| {
                let tx = tx.clone();
                async move {
                    let sender = tx.lock().await.take();
                    if let Some(sender) = sender {
                        if let Some(error) = params.error {
                            let desc = params.error_description.unwrap_or_default();
                            let _ = sender.send(Err(format!("OAuth error: {} - {}", error, desc)));
                        } else if let (Some(code), Some(state)) = (params.code, params.state) {
                            let _ = sender.send(Ok((code, state)));
                        } else {
                            let _ = sender.send(Err("Missing code or state in callback".to_string()));
                        }
                    }
                    Html(
                        "<html><body><h2>Authentication successful</h2>\
                         <p>You can close this tab.</p></body></html>"
                            .to_string(),
                    )
                }
            }),
        );

        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .ok();
    });

    let callback_result = tokio::time::timeout(std::time::Duration::from_secs(120), rx)
        .await
        .map_err(|_| "OIDC login timed out (120s). Please try again.".to_string())?
        .map_err(|_| "Callback channel closed unexpectedly".to_string())?
        .map_err(|e| e)?;

    let (auth_code, returned_state) = callback_result;

    // 9. Validate state
    if returned_state != state_nonce {
        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
        return Err("OIDC state mismatch — possible CSRF attack".to_string());
    }

    // 10. Exchange code for tokens
    let token_body = {
        let mut s = url::form_urlencoded::Serializer::new(String::new());
        s.append_pair("grant_type", "authorization_code")
            .append_pair("code", &auth_code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("client_id", &client_id)
            .append_pair("code_verifier", &code_verifier);
        if let Some(ref secret) = client_secret {
            s.append_pair("client_secret", secret);
        }
        s.finish()
    };

    let token_resp: TokenResponse = state
        .http_client
        .post(&discovery.token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(token_body)
        .send()
        .await
        .map_err(|e| format!("Token exchange failed: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse token response: {}", e))?;

    let id_token = token_resp
        .id_token
        .ok_or_else(|| "Token response did not contain id_token".to_string())?;

    // 11. Decode claims for display (unverified — helper validates when used)
    let claims = decode_jwt_claims_unverified(&id_token).unwrap_or(IdTokenClaims {
        sub: "unknown".to_string(),
        email: None,
        name: None,
    });

    // 12. Store token in app state
    *state.helper_token.lock().unwrap() = Some(id_token.clone());

    // 13. Shut down temp server
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    // 14. Return result to frontend
    Ok(OidcLoginResult {
        token: id_token,
        email: claims.email,
        name: claims.name,
        provider: provider_name,
    })
}

// =============================================================================
// App Entry Point
// =============================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // Connection
            connect,
            disconnect,
            get_connection_status,
            // Components
            list_components,
            get_component,
            list_apps,
            list_sub_entity_apps,
            get_app_detail,
            // Data
            list_parameters,
            read_parameter,
            read_parameter_raw,
            write_parameter,
            // ECU Info
            get_ecu_info,
            // I/O Control
            list_io_controls,
            io_control,
            // Export Logs
            export_logs,
            // Faults
            list_faults,
            clear_faults,
            // Operations
            list_operations,
            execute_operation,
            // Session/Security
            get_session,
            set_session,
            get_security,
            request_security_seed,
            send_security_key,
            // Security Helper
            set_security_helper,
            security_helper_info,
            security_helper_calculate,
            oidc_login,
            // Flash/Software Update
            flash_init,
            flash_list_transfers,
            flash_upload,
            flash_upload_from_path,
            flash_poll_upload,
            flash_verify,
            flash_start,
            flash_poll_progress,
            flash_abort,
            flash_finalize,
            flash_reset_ecu,
            flash_commit,
            flash_rollback,
            flash_get_activation,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
