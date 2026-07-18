use serde::{Deserialize, Serialize};
use sovd_client::{
    AppInfo, Component, DataResponse, FaultInfo, FlashClient, FlashConfig, OperationExecution,
    OperationInfo, ParameterInfo, SovdClient,
};
use sovd_core::EntityStatus;
use sovd_uds::uds::standard_did;
use std::collections::HashMap;
use std::sync::Mutex;
use tauri::State;

// =============================================================================
// State Management
// =============================================================================

struct AppState {
    client: Mutex<Option<SovdClient>>,
    server_url: Mutex<String>,
    /// Skip TLS certificate verification (the `curl -k` equivalent) for the
    /// active connection. Set at `connect`; reused by the flash client so it
    /// dials the device on the same trust terms. Default `false`.
    insecure: Mutex<bool>,
    flash_client: Mutex<Option<FlashClient>>,
    current_flash_component: Mutex<Option<String>>,
    /// Gateway id for the in-flight flash, if the target is a sub-entity.
    /// Used to route identData (F189) version reads through the gateway.
    current_flash_gateway: Mutex<Option<String>>,
    /// HTTP client for the OIDC flow (discovery + token exchange).
    http_client: reqwest::Client,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            client: Mutex::new(None),
            server_url: Mutex::new("http://localhost:4000".to_string()),
            insecure: Mutex::new(false),
            flash_client: Mutex::new(None),
            current_flash_component: Mutex::new(None),
            current_flash_gateway: Mutex::new(None),
            http_client: reqwest::Client::new(),
        }
    }
}

/// Get a cloned client (SovdClient is Clone)
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
}

// =============================================================================
// Connection Commands
// =============================================================================

#[tauri::command]
async fn connect(
    state: State<'_, AppState>,
    server_url: String,
    insecure: bool,
) -> Result<ConnectionStatus, String> {
    match SovdClient::new_insecure(&server_url, insecure) {
        Ok(client) => {
            // Test the connection with a health check
            match client.health().await {
                Ok(_) => {
                    *state.client.lock().unwrap() = Some(client);
                    *state.server_url.lock().unwrap() = server_url.clone();
                    *state.insecure.lock().unwrap() = insecure;
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

// Raw/unconverted bytes are NOT a separate read command. Every normal read already
// carries them in `DataResponse.raw` (rendered directly by the frontend's raw-cell).
// The old `?raw=true` path (read_data_raw) was removed: it routed to the server's
// `read_raw_did`, which aggregating entities (gateways) don't implement, so it 501'd.
// The normal read works through gateways (read_data forwards to children) and the
// `raw` field is the spec-aligned way to expose unconverted bytes.

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
            client
                .read_sub_entity_data(&component_id, path, &did_str)
                .await
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
                client
                    .read_sub_entity_data(&component_id, path, param)
                    .await
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
        let (
            name,
            current_state,
            value,
            default_value,
            allowed,
            controlled_by_tester,
            frozen,
            requires_security,
            security_level,
        ) = if let Some(ref d) = detail {
            (
                d.name
                    .clone()
                    .unwrap_or_else(|| o.name.clone().unwrap_or_else(|| o.id.clone())),
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
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                o.security_level,
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

    match client
        .control_output(&component_id, &data_id, sovd_action, value)
        .await
    {
        Ok(response) => Ok(IoControlResponse {
            success: response.success,
            state: if response.controlled_by_tester {
                "controlled"
            } else {
                "released"
            }
            .to_string(),
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

    let mut file =
        std::fs::File::create(&path).map_err(|e| format!("Failed to create file: {}", e))?;
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
    // Kept on the Tauri surface for the JS caller — the spec-conforming
    // wire only models "start", but UDS RoutineControl semantics live
    // in `action`.  Stop / result polling go through separate commands
    // when needed (not wired yet).
    _action: String,
) -> Result<OperationExecution, String> {
    let client = get_client(&state)?;
    client
        .start_operation_execution(&component_id, &operation_id, None)
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
            .unwrap_or(session),
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

    Ok(SecurityInfo {
        id: mode.id,
        value: mode
            .value
            .and_then(|v| v.as_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "locked".to_string()),
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
    /// True while the banked trial is paused awaiting a commit/rollback
    /// verdict (`x-sumo-substate == awaiting-verdict`).
    pub supports_rollback: bool,
    /// Frontend-normalized lifecycle state (see `normalize_update_state`).
    pub state: String,
    /// Installed software version (identData DID F189), if readable.
    pub active_version: Option<String>,
    /// No `/updates` equivalent — always None (kept for frontend shape).
    pub previous_version: Option<String>,
}

/// Converged runtime status from `GET /{entity}/status` (ISO 17978-3 §7.19.2).
/// `ready` is the standard `EntityStatus` (`Ready` → `true`); the rest are the
/// vendor `x-sumo-runtime` passthrough: `boot_id` (per-guest-lifetime nonce —
/// the canonical "has-rebooted" signal), `hb_seq` (heartbeat liveness,
/// advances ~1/s) and `boot_count` (NV reset counter). All optional: the
/// vendor block may be absent on a spec-pure entity.
#[derive(Debug, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub ready: Option<bool>,
    pub boot_id: Option<u32>,
    pub hb_seq: Option<u32>,
    pub boot_count: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitRollbackResult {
    pub success: bool,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UploadResult {
    /// The latched `/updates` update_id (the part is uploaded into this id).
    pub upload_id: String,
    /// The part id the bytes landed under (e.g. "manifest").
    pub file_id: Option<String>,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlashResult {
    /// The `/updates` update_id (no separate transfer id on the spec wire).
    pub transfer_id: String,
    /// Frontend-normalized lifecycle state (see `normalize_update_state`).
    pub state: String,
    /// No block-level accounting on `/updates` — always 0 (kept for shape).
    pub blocks_transferred: u32,
    pub blocks_total: u32,
    /// `UpdateStatusBody.progress` (0..=100), if reported.
    pub percent: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransferInfo {
    /// A registered update_id from `GET /updates`.
    pub transfer_id: String,
    pub state: String,
    pub error: Option<String>,
}

/// Map an ISO 17978-3 §7.18.7 `UpdateStatusBody` onto the snake_case
/// lifecycle strings the frontend's `normalizeFlashState` understands.
///
/// - `status == "failed"`                        → `failed`
/// - `x-sumo-substate == "awaiting-verdict"`     → `activated` (banked trial paused)
/// - `x-sumo-substate == "rolling-back"`         → `rolled_back`
/// - `x-sumo-substate == "committing"`           → `committed`
/// - `status == "completed"` (prepare)           → `complete` (parts verified)
/// - `status == "completed"` (execute/other)     → `complete`
/// - otherwise (running)                         → `transferring`
fn normalize_update_state(body: &sovd_client::flash::UpdateStatusBody) -> String {
    if body.status == "failed" {
        return "failed".to_string();
    }
    match body.substate.as_deref() {
        Some("awaiting-verdict") => return "activated".to_string(),
        Some("rolling-back") => return "rolled_back".to_string(),
        Some("committing") => return "committed".to_string(),
        _ => {}
    }
    if body.status == "completed" {
        "complete".to_string()
    } else {
        "transferring".to_string()
    }
}

/// Read the installed software version (identData DID F189) via the
/// connected `SovdClient`.  On `/updates`, version is identData, not a
/// field on the flash wire.  Best-effort: returns None on any failure.
async fn read_installed_version(
    state: &State<'_, AppState>,
    component_id: &str,
    app_path: Option<&str>,
) -> Option<String> {
    let client = state.client.lock().unwrap().clone()?;
    let result = if let Some(path) = app_path {
        client
            .read_sub_entity_data(component_id, path, "F189")
            .await
    } else {
        client.read_data(component_id, "F189").await
    };
    match result {
        Ok(data) => {
            if let Some(v) = data.value.as_str() {
                Some(v.to_string())
            } else if data.value.is_null() {
                None
            } else {
                Some(data.value.to_string())
            }
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Flash-driving commands — re-implemented on the ISO 17978-3 §7.18 `/updates`
// wire.  The old `/files`+`/flash` verbs (start_flash / upload_file /
// verify_file / transfer_exit / get_flash_status / commit_flash / ...) are
// gone; each command body below maps onto the `/updates` lifecycle:
//
//   open_update → upload_part("manifest", ..) → prepare() → execute(true)
//                 → spec_commit() | spec_rollback()
//
// FlashClient latches the update_id internally after open_update/upload, so
// per-step commands no longer thread a transfer_id (the JS still passes one
// for backward shape; it is the update_id and is ignored on the wire).
// ---------------------------------------------------------------------------

/// Pull the current flash client out of state, or error if uninitialized.
fn take_flash_client(state: &State<'_, AppState>) -> Result<FlashClient, String> {
    state
        .flash_client
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "Flash client not initialized. Call flash_init first.".to_string())
}

/// `GET /updates` — registered update_ids on this component.  On `/updates`,
/// a listed id is an in-flight session (cleared server-side on commit /
/// rollback), so the frontend treats each as an existing transfer to cancel.
/// State is reported as `registered`: real lifecycle state requires attaching,
/// which would mutate the client's latched id, so we don't poll it here.
#[tauri::command]
async fn flash_list_transfers(state: State<'_, AppState>) -> Result<Vec<TransferInfo>, String> {
    let flash_client = take_flash_client(&state)?;

    let ids = flash_client
        .list_updates()
        .await
        .map_err(|e| format!("Failed to list updates: {}", e))?;

    Ok(ids
        .into_iter()
        .map(|id| TransferInfo {
            transfer_id: id,
            state: "registered".to_string(),
            error: None,
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
    // Reuse the trust decision the operator made at connect, so the flash
    // client dials the device on the same TLS terms as the browse client.
    let insecure = *state.insecure.lock().unwrap();

    let mut config = FlashConfig::builder(&server_url).component_id(&component_id);
    if let Some(ref gw) = gateway_id {
        config = config.gateway_id(gw);
    }
    let flash_client = FlashClient::new(config.insecure(insecure).build())
        .map_err(|e| format!("Failed to create flash client: {}", e))?;

    *state.flash_client.lock().unwrap() = Some(flash_client);
    *state.current_flash_component.lock().unwrap() = Some(component_id);
    *state.current_flash_gateway.lock().unwrap() = gateway_id;

    Ok(true)
}

/// Open a `/updates` session (if not already open) and stream the package in
/// as the `manifest` part — the SUIT envelope.  Upload is synchronous on the
/// spec wire (the PUT returns once the part is stored), so there is no
/// separate upload-poll step.  `upload_id` is the latched update_id.
async fn upload_manifest_part(
    flash_client: &FlashClient,
    data: &[u8],
) -> Result<UploadResult, String> {
    // Lazily opens the update session if none is open yet.
    let part = flash_client
        .upload_part("manifest", data)
        .await
        .map_err(|e| format!("Upload failed: {}", e))?;

    let update_id = flash_client.current_update_id().await.unwrap_or_default();

    Ok(UploadResult {
        upload_id: update_id,
        file_id: Some(part.part_id),
        state: "complete".to_string(),
    })
}

#[tauri::command]
async fn flash_upload(
    state: State<'_, AppState>,
    data: Vec<u8>,
    // Retained for backward call shape; `/updates` parts are keyed by part_id
    // ("manifest"), not the source filename.
    filename: Option<String>,
) -> Result<UploadResult, String> {
    let _ = filename;
    let flash_client = take_flash_client(&state)?;
    upload_manifest_part(&flash_client, &data).await
}

#[tauri::command]
async fn flash_upload_from_path(
    state: State<'_, AppState>,
    path: String,
) -> Result<UploadResult, String> {
    let data =
        std::fs::read(&path).map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
    let flash_client = take_flash_client(&state)?;
    upload_manifest_part(&flash_client, &data).await
}

/// Upload is synchronous on `/updates`; this is a back-compat echo so the
/// frontend's optional upload-poll step still resolves.
#[tauri::command]
async fn flash_poll_upload(
    state: State<'_, AppState>,
    upload_id: String,
) -> Result<UploadResult, String> {
    let _ = take_flash_client(&state)?;
    Ok(UploadResult {
        upload_id,
        file_id: Some("manifest".to_string()),
        state: "complete".to_string(),
    })
}

/// `PUT /updates/{id}/prepare` — verifies the uploaded parts (manifest).
/// Async on the wire: the client polls `/status` to terminal internally.
/// Returns true iff prepare reached `status == completed`.
#[tauri::command]
async fn flash_verify(
    state: State<'_, AppState>,
    // Old wire keyed verify by file_id; the spec verb operates on the latched
    // update session, so the argument is accepted but unused.
    file_id: String,
) -> Result<bool, String> {
    let _ = file_id;
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .prepare()
        .await
        .map_err(|e| format!("Prepare/verify failed: {}", e))?;

    if body.status != "completed" {
        return Err(format!(
            "Prepare ended at {}/{}{}",
            body.phase,
            body.status,
            body.error
                .map(|e| format!(": {}", e.message))
                .unwrap_or_default()
        ));
    }
    Ok(true)
}

/// `PUT /updates/{id}/execute?x-sumo-control=orchestrated` — installs /
/// activates the staged parts and pauses the banked trial at
/// `awaiting-verdict` so the UI can offer Commit / Rollback.  The client
/// polls `/status` internally; we map the terminal `UpdateStatusBody` onto
/// the frontend's lifecycle state string.
#[tauri::command]
async fn flash_start(
    state: State<'_, AppState>,
    // Old wire keyed flash-start by file_id; superseded by the latched
    // update session.  Accepted but unused.
    file_id: String,
) -> Result<FlashResult, String> {
    let _ = file_id;
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .execute(true)
        .await
        .map_err(|e| format!("Failed to execute update: {}", e))?;

    Ok(FlashResult {
        transfer_id: flash_client.current_update_id().await.unwrap_or_default(),
        state: normalize_update_state(&body),
        blocks_transferred: 0,
        blocks_total: 0,
        percent: body.progress.map(|p| p as f64),
        error: body.error.map(|e| e.message),
    })
}

/// `GET /updates/{id}/status` — the §7.18.7 lifecycle status, mapped onto a
/// `FlashResult`.  Replaces the old per-transfer `get_flash_status`.
#[tauri::command]
async fn flash_poll_progress(
    state: State<'_, AppState>,
    // The latched update session is the source of truth; the id is accepted
    // for back-compat but not used to address the wire.
    transfer_id: String,
) -> Result<FlashResult, String> {
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .spec_status()
        .await
        .map_err(|e| format!("Failed to get update status: {}", e))?;

    Ok(FlashResult {
        transfer_id,
        state: normalize_update_state(&body),
        blocks_transferred: 0,
        blocks_total: 0,
        percent: body.progress.map(|p| p as f64),
        error: body.error.map(|e| e.message),
    })
}

/// Abort: there is no `delete_update` on the current client, so abort maps to
/// the trial-recovery vendor verb `PUT /components/{id}/x-sumo-force-rollback`
/// (idempotent; unsticks a banked trial / abandoned session). Clears the
/// in-process flash state afterwards.
#[tauri::command]
async fn flash_abort(
    state: State<'_, AppState>,
    // No transfer to address on the spec wire; force-rollback acts on the
    // component's trial. Accepted but unused.
    transfer_id: String,
) -> Result<bool, String> {
    let _ = transfer_id;
    let flash_client = take_flash_client(&state)?;

    flash_client
        .force_rollback()
        .await
        .map_err(|e| format!("Failed to abort (force-rollback) update: {}", e))?;

    Ok(true)
}

/// Finalize is folded into `execute` on `/updates` (PUT /execute installs +
/// activates). Kept as a back-compat no-op that confirms the session is still
/// reachable, so the frontend's discrete "Finalize" step resolves cleanly.
#[tauri::command]
async fn flash_finalize(state: State<'_, AppState>) -> Result<bool, String> {
    let flash_client = take_flash_client(&state)?;
    // Best-effort touch; ignore status — execute already finalized.
    let _ = flash_client.spec_status().await;
    Ok(true)
}

/// ECU reset (`PUT /components/{id}/status/restart`) — lives at the entity
/// root, unchanged by the `/updates` migration.  The current API requires a
/// reset_type; the explorer uses a hard reset.
#[tauri::command]
async fn flash_reset_ecu(state: State<'_, AppState>) -> Result<bool, String> {
    let flash_client = take_flash_client(&state)?;

    flash_client
        .ecu_reset("hardReset")
        .await
        .map_err(|e| format!("ECU reset failed: {}", e))?;

    Ok(true)
}

/// `PUT /updates/{id}/x-sumo-commit` — accept the banked trial. The client
/// clears its latched update_id on success; we also clear app-side flash
/// state so a fresh cycle can begin.
#[tauri::command]
async fn flash_commit(state: State<'_, AppState>) -> Result<CommitRollbackResult, String> {
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .spec_commit()
        .await
        .map_err(|e| format!("Commit failed: {}", e))?;

    *state.flash_client.lock().unwrap() = None;
    *state.current_flash_component.lock().unwrap() = None;
    *state.current_flash_gateway.lock().unwrap() = None;

    let success = body.status == "completed";
    Ok(CommitRollbackResult {
        success,
        message: body.error.map(|e| e.message),
    })
}

/// `PUT /updates/{id}/x-sumo-rollback` — reject the banked trial. Same state
/// cleanup as commit.
#[tauri::command]
async fn flash_rollback(state: State<'_, AppState>) -> Result<CommitRollbackResult, String> {
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .spec_rollback()
        .await
        .map_err(|e| format!("Rollback failed: {}", e))?;

    *state.flash_client.lock().unwrap() = None;
    *state.current_flash_component.lock().unwrap() = None;
    *state.current_flash_gateway.lock().unwrap() = None;

    let success = body.status == "completed";
    Ok(CommitRollbackResult {
        success,
        message: body.error.map(|e| e.message),
    })
}

/// Activation state on `/updates` is the §7.18.7 lifecycle status itself.
/// `supports_rollback` is true while the trial is paused at
/// `awaiting-verdict`; the installed version comes from identData DID F189
/// (read through the connected `SovdClient`, routed via the gateway for
/// sub-entities). `previous_version` has no `/updates` equivalent.
#[tauri::command]
async fn flash_get_activation(state: State<'_, AppState>) -> Result<ActivationInfo, String> {
    let flash_client = take_flash_client(&state)?;

    let body = flash_client
        .spec_status()
        .await
        .map_err(|e| format!("Failed to get update status: {}", e))?;

    // Resolve where to read the version DID: sub-entity reads go through the
    // gateway (component = gateway, app_path = flash component); top-level
    // reads address the component directly.
    let component = state.current_flash_component.lock().unwrap().clone();
    let gateway = state.current_flash_gateway.lock().unwrap().clone();
    let active_version = match (gateway, component) {
        (Some(gw), Some(app)) => read_installed_version(&state, &gw, Some(&app)).await,
        (None, Some(comp)) => read_installed_version(&state, &comp, None).await,
        _ => None,
    };

    Ok(ActivationInfo {
        supports_rollback: body.is_awaiting_verdict(),
        state: normalize_update_state(&body),
        active_version,
        previous_version: None,
    })
}

/// `GET /vehicle/v1/components/{id}/status` — the converged runtime status
/// (ISO 17978-3 §7.19.2). Independent of any in-flight flash session: it reads
/// through the connected `SovdClient`, not the flash client. Maps the standard
/// `EntityStatus` onto `ready`, and surfaces the vendor `x-sumo-runtime`
/// passthrough (`boot_id` lifetime nonce, `hb_seq` heartbeat, `boot_count` NV
/// reset counter). Vendor fields are best-effort — absent ones stay `None`.
#[tauri::command]
async fn read_status(
    state: State<'_, AppState>,
    component_id: String,
) -> Result<RuntimeStatus, String> {
    let client = get_client(&state)?;

    let body = client
        .read_status(&component_id)
        .await
        .map_err(|e| format!("Failed to read status: {}", e))?;

    let ready = Some(body.status == EntityStatus::Ready);

    let runtime = body.extensions.get("x-sumo-runtime");
    let field = |key: &str| runtime.and_then(|r| r.get(key)).and_then(|v| v.as_u64());

    Ok(RuntimeStatus {
        ready,
        boot_id: field("boot_id").map(|n| n as u32),
        hb_seq: field("hb_seq").map(|n| n as u32),
        boot_count: field("boot_count"),
    })
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
    serde_json::from_slice(&payload).map_err(|e| format!("Failed to parse JWT claims: {}", e))
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
    issuer: String,
    client_id: String,
    client_secret: Option<String>,
) -> Result<OidcLoginResult, String> {
    // 1. Fetch OIDC discovery document from the configured issuer
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

    // 2. Generate PKCE code_verifier and code_challenge (S256)
    use sha2::Digest;
    let verifier_bytes: [u8; 32] = rand::random();
    let code_verifier = base64_url_encode(&verifier_bytes);
    let challenge_hash = sha2::Sha256::digest(code_verifier.as_bytes());
    let code_challenge = base64_url_encode(&challenge_hash);

    // 3. Generate random state nonce
    let state_bytes: [u8; 16] = rand::random();
    let state_nonce = hex::encode(state_bytes);

    // 4. Bind temporary localhost callback server (OS picks free port)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("Failed to bind callback listener: {}", e))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get listener address: {}", e))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{}/callback", port);

    // 5. Construct authorization URL
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

    // 6. Open browser
    open::that(&auth_url).map_err(|e| format!("Failed to open browser: {}", e))?;

    // 7. Wait for callback (with 120s timeout)
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(String, String), String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server_handle = tokio::spawn(async move {
        use axum::{
            extract::Query, response::Html, routing::get as axum_get, Router as AxumRouter,
        };

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
                            let _ =
                                sender.send(Err("Missing code or state in callback".to_string()));
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
        .map_err(|_| "Callback channel closed unexpectedly".to_string())??;

    let (auth_code, returned_state) = callback_result;

    // 8. Validate state
    if returned_state != state_nonce {
        let _ = shutdown_tx.send(());
        let _ = server_handle.await;
        return Err("OIDC state mismatch — possible CSRF attack".to_string());
    }

    // 9. Exchange code for tokens
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

    // 10. Decode claims for display (unverified — the SOVD server validates
    //     the token when it is used)
    let claims = decode_jwt_claims_unverified(&id_token).unwrap_or(IdTokenClaims {
        sub: "unknown".to_string(),
        email: None,
        name: None,
    });

    // 11. Shut down temp server
    let _ = shutdown_tx.send(());
    let _ = server_handle.await;

    // 12. Return result to frontend (the frontend keeps the token as the
    //     bearer credential for SOVD requests)
    Ok(OidcLoginResult {
        token: id_token,
        email: claims.email,
        name: claims.name,
        provider: issuer,
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
            // Auth (OIDC)
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
            read_status,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
