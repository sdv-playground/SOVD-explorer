import React, { useState, useEffect, useCallback, useRef, createContext, useContext } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import "./App.css";

// =============================================================================
// Types from Tauri backend
// =============================================================================

interface ConnectionStatus {
  connected: boolean;
  server_url: string;
  error: string | null;
}

interface ComponentCapabilities {
  read_data?: boolean;
  write_data?: boolean;
  faults?: boolean;
  clear_faults?: boolean;
  logs?: boolean;
  operations?: boolean;
  software_update?: boolean;
  io_control?: boolean;
  sessions?: boolean;
  security?: boolean;
  sub_entities?: boolean;
  subscriptions?: boolean;
}

interface Component {
  id: string;
  name: string;
  type?: string;
  href?: string;
  capabilities?: ComponentCapabilities;
}

interface ComponentTreeNode {
  component: Component;
  children: ComponentTreeNode[];
  expanded: boolean;
  /** If this node is a sub-entity, the root gateway component ID */
  parentGatewayId?: string;
  /** Full prefix path from the root gateway (e.g., "uds_gw/engine_ecu" for engine_ecu under uds_gw) */
  pathPrefix?: string;
}

interface AppInfo {
  id: string;
  name: string;
  description?: string;
  status?: string;
  type?: string;
  href?: string;
  capabilities?: ComponentCapabilities;
}

interface ParameterInfo {
  id: string;
  did: string;
  name?: string;
  data_type?: string;
  unit?: string;
  writable?: boolean;
  href: string;
}

interface DataResponse {
  did?: string;
  value: unknown;
  unit?: string;
  raw?: string;
  length?: number;
  converted?: boolean;
  timestamp?: number;
}

interface FaultInfo {
  id: string;
  code: string;
  message: string;
  severity: string;
  category?: string;
  active: boolean;
  href: string;
}

interface OperationInfo {
  id: string;
  name: string;
  description?: string;
  requires_security: boolean;
  security_level?: number;
  href: string;
}

interface OperationResponse {
  operation_id: string;
  action: string;
  status: string;
  result_data?: string;
  error?: string;
  timestamp: number;
}

interface SessionInfo {
  id: string;
  value: string;
}

interface SecurityInfo {
  id: string;
  value: string;
  seed?: string;
}

// =============================================================================
// Normalized UI types — single source of truth for state mapping
// =============================================================================

type SecurityState = "locked" | "unlocked";
type SessionMode = "default" | "extended" | "programming" | "engineering";

const SESSION_MODES: SessionMode[] = ["default", "extended", "programming", "engineering"];

function parseSecurityState(raw: string): SecurityState {
  if (raw === "locked" || raw.includes("seedavailable")) return "locked";
  return "unlocked";
}

function parseSessionMode(raw: string): SessionMode {
  const lower = raw.toLowerCase();
  if (SESSION_MODES.includes(lower as SessionMode)) return lower as SessionMode;
  return "default";
}

function sessionModeLabel(mode: SessionMode): string {
  return mode.charAt(0).toUpperCase() + mode.slice(1);
}

// Log Entry for diagnostic session logging
interface LogEntry {
  timestamp: string;
  type: "read" | "write" | "operation" | "error" | "info";
  component: string;
  action: string;
  details: string;
  success: boolean;
}

// Log Context for sharing logging across components
interface LogContextValue {
  logs: LogEntry[];
  addLog: (entry: Omit<LogEntry, "timestamp">) => void;
  clearLogs: () => void;
}

const LogContext = createContext<LogContextValue | null>(null);

// Hook for accessing log context in child components
const useLog = () => {
  const context = useContext(LogContext);
  if (!context) {
    // Return a no-op logger if context not available
    return {
      logs: [],
      addLog: () => {},
      clearLogs: () => {},
    };
  }
  return context;
};

// =============================================================================
// Security Helper Types
// =============================================================================

interface HelperProviderInfo {
  name: string;
  issuer: string;
  client_id?: string;
}

interface OidcLoginResult {
  token: string;
  email: string | null;
  name: string | null;
  provider: string;
}

interface HelperInfo {
  name: string;
  version: string;
  auth_mode: string;
  providers?: HelperProviderInfo[];
  supported_ecus: string[];
}

interface HelperResult {
  success: boolean;
  key?: string;
  error?: string;
}

// =============================================================================
// Helper Functions
// =============================================================================

function hexToAscii(hex: string): string {
  let str = "";
  for (let i = 0; i < hex.length; i += 2) {
    const code = parseInt(hex.substr(i, 2), 16);
    if (code >= 32 && code <= 126) {
      str += String.fromCharCode(code);
    } else {
      return hex;
    }
  }
  return str;
}

// =============================================================================
// Main App Component
// =============================================================================

function App() {
  const [serverUrl, setServerUrl] = useState("http://localhost:4000");
  const [connected, setConnected] = useState(false);
  const [componentTree, setComponentTree] = useState<ComponentTreeNode[]>([]);
  const [selectedComponent, setSelectedComponent] = useState<string | null>(null);
  const [gatewayContext, setGatewayContext] = useState<string | null>(null);
  const [selectedPathPrefix, setSelectedPathPrefix] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Log state
  const [logs, setLogs] = useState<LogEntry[]>([]);

  // Security Helper state (top-level, same as SOVD server)
  const [helperUrl, setHelperUrl] = useState<string>(() => localStorage.getItem("sovd_helper_url") || "http://localhost:9100");
  const [helperToken, setHelperToken] = useState<string>(() => localStorage.getItem("sovd_helper_token") || "dev-secret-123");
  const [helperConnected, setHelperConnected] = useState(false);
  const [helperInfo, setHelperInfo] = useState<HelperInfo | null>(null);

  // OIDC login state
  const [oidcUser, setOidcUser] = useState<{ email: string; provider: string } | null>(null);
  const [oidcLoggingIn, setOidcLoggingIn] = useState(false);

  // Settings panel state — open by default on first visit
  const [settingsOpen, setSettingsOpen] = useState<boolean>(() => {
    const stored = localStorage.getItem("sovd_settings_open");
    return stored === null ? true : stored === "true";
  });

  const addLog = useCallback((entry: Omit<LogEntry, "timestamp">) => {
    const newEntry: LogEntry = {
      ...entry,
      timestamp: new Date().toISOString(),
    };
    setLogs(prev => [...prev, newEntry]);
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  const checkConnection = async () => {
    try {
      const status = await invoke<ConnectionStatus>("connect", { serverUrl });
      setConnected(status.connected);
      if (status.error) {
        setError(status.error);
      } else {
        setError(null);
        fetchComponents();
      }
    } catch (e) {
      setConnected(false);
      setError(`Connection failed: ${e}`);
    }
  };

  const fetchComponents = async () => {
    // Recursively fetch apps for a sub-entity that may itself have children
    // parentPath is the prefix path so far (e.g., "uds_gw" for children of uds_gw)
    const fetchSubEntityChildren = async (
      rootGatewayId: string,
      subGatewayId: string,
      parentPath: string,
    ): Promise<ComponentTreeNode[]> => {
      try {
        const apps = await invoke<AppInfo[]>("list_sub_entity_apps", {
          componentId: rootGatewayId,
          appId: subGatewayId,
        });
        const children: ComponentTreeNode[] = [];
        for (const app of apps) {
          const childPath = `${parentPath}/${app.id}`;
          const grandchildren = await fetchSubEntityChildren(rootGatewayId, `${subGatewayId}/${app.id}`, childPath);
          children.push({
            component: { id: app.id, name: app.name, type: app.type, href: app.href },
            children: grandchildren,
            expanded: grandchildren.length > 0,
            parentGatewayId: rootGatewayId,
            pathPrefix: childPath,
          });
        }
        return children.sort((a, b) => a.component.name.localeCompare(b.component.name));
      } catch (e) {
        console.warn(`Failed to fetch sub-entity apps for ${subGatewayId}:`, e);
        return [];
      }
    };

    try {
      const comps = await invoke<Component[]>("list_components");
      // Fetch detail for each component to get capabilities (list endpoint doesn't include them per SOVD spec)
      const detailed = await Promise.all(
        comps.map(async (c) => {
          try {
            return await invoke<Component>("get_component", { componentId: c.id });
          } catch {
            return c; // fall back to slim info
          }
        })
      );
      const hasSubEntities = (c: Component) => c.type === "gateway" || c.capabilities?.sub_entities === true;
      const parents = detailed.filter(hasSubEntities);
      const others = detailed.filter(c => !hasSubEntities(c))
        .sort((a, b) => a.name.localeCompare(b.name));

      const tree: ComponentTreeNode[] = [];

      // Build subtrees from list_apps for gateways and entities with sub_entities
      for (const parent of parents) {
        const children: ComponentTreeNode[] = [];
        try {
          const apps = await invoke<AppInfo[]>("list_apps", { componentId: parent.id });
          for (const app of apps) {
            const childPath = app.id;
            const grandchildren = await fetchSubEntityChildren(parent.id, app.id, childPath);
            children.push({
              component: { id: app.id, name: app.name, type: app.type, href: app.href },
              children: grandchildren,
              expanded: grandchildren.length > 0,
              parentGatewayId: parent.id,
              pathPrefix: childPath,
            });
          }
        } catch (e) {
          console.warn(`Failed to fetch apps for ${parent.id}:`, e);
        }
        tree.push({
          component: parent,
          children: children.sort((a, b) => a.component.name.localeCompare(b.component.name)),
          expanded: true,
        });
      }

      // Non-gateway, non-child components stay as root nodes
      for (const comp of others) {
        tree.push({ component: comp, children: [], expanded: false });
      }

      setComponentTree(tree);
    } catch (e) {
      console.error("Failed to fetch components:", e);
    }
  };

  const toggleTreeNode = (nodeId: string) => {
    const toggleInTree = (nodes: ComponentTreeNode[]): ComponentTreeNode[] =>
      nodes.map(node => {
        if (node.component.id === nodeId) {
          return { ...node, expanded: !node.expanded };
        }
        if (node.children.length > 0) {
          return { ...node, children: toggleInTree(node.children) };
        }
        return node;
      });
    setComponentTree(prev => toggleInTree(prev));
  };

  const renderTreeNode = (node: ComponentTreeNode): JSX.Element => {
    const hasChildren = node.children.length > 0;
    const isGateway = node.component.type === "gateway";
    const typeBadge = isGateway ? "GW" : node.component.type === "app" ? "APP" : null;

    if (hasChildren) {
      return (
        <li key={node.component.id} className="tree-node">
          <div
            className={`tree-parent ${selectedComponent === node.component.id ? "selected" : ""}`}
            onClick={() => { setSelectedComponent(node.component.id); setGatewayContext(node.parentGatewayId || null); setSelectedPathPrefix(node.pathPrefix || null); }}
          >
            <span
              className={`tree-toggle ${node.expanded ? "expanded" : ""}`}
              onClick={(e) => { e.stopPropagation(); toggleTreeNode(node.component.id); }}
            />
            <span className="tree-label">{node.component.name || node.component.id}</span>
            {typeBadge && <span className="tree-type-badge">{typeBadge}</span>}
          </div>
          {node.expanded && (
            <ul className="tree-children">
              {node.children.map((child) => renderTreeNode(child))}
            </ul>
          )}
        </li>
      );
    }

    return (
      <li key={node.component.id} className="tree-node">
        <div
          className={`tree-leaf ${selectedComponent === node.component.id ? "selected" : ""}`}
          onClick={() => { setSelectedComponent(node.component.id); setGatewayContext(node.parentGatewayId || null); setSelectedPathPrefix(node.pathPrefix || null); }}
        >
          <span className="tree-label">{node.component.name || node.component.id}</span>
          {typeBadge && <span className="tree-type-badge">{typeBadge}</span>}
        </div>
      </li>
    );
  };

  // Probe helper to discover its auth_mode without requiring a token
  // Probe helper to discover its auth_mode. Sets helperInfo for UI rendering
  // but does NOT mark helperConnected — ensureHelper handles that with the real token.
  const probeHelper = useCallback(async () => {
    try {
      // Temporarily set URL so security_helper_info can reach it, but use
      // the real token so we don't clobber backend state for static mode.
      await invoke("set_security_helper", { url: helperUrl, token: helperToken });
      const info = await invoke<HelperInfo>("security_helper_info");
      setHelperInfo(info);
      setHelperConnected(false); // force ensureHelper to re-run with proper token
      localStorage.setItem("sovd_helper_url", helperUrl);
    } catch (e) {
      setHelperInfo(null);
      setHelperConnected(false);
      setError(`Helper probe failed: ${e}`);
    }
  }, [helperUrl, helperToken]);

  // OIDC login — launches browser-based sign-in flow
  const oidcLogin = useCallback(async (providerName: string) => {
    setOidcLoggingIn(true);
    setError(null);
    try {
      // Set helper URL (token empty — will be set by oidc_login command)
      await invoke("set_security_helper", { url: helperUrl, token: "" });
      const result = await invoke<OidcLoginResult>("oidc_login", { providerName });
      // Store the returned token
      setHelperToken(result.token);
      localStorage.setItem("sovd_helper_token", result.token);
      localStorage.setItem("sovd_helper_url", helperUrl);
      setOidcUser({
        email: result.email || result.provider,
        provider: result.provider,
      });
      // Re-probe helper to confirm connection with the new token
      setHelperConnected(false);
      setHelperInfo(null);
      await invoke("set_security_helper", { url: helperUrl, token: result.token });
      const info = await invoke<HelperInfo>("security_helper_info");
      setHelperInfo(info);
      setHelperConnected(true);
    } catch (e) {
      setError(`OIDC login failed: ${e}`);
    } finally {
      setOidcLoggingIn(false);
    }
  }, [helperUrl]);

  // OIDC sign out — clear token and user state
  const oidcSignOut = useCallback(() => {
    setOidcUser(null);
    setHelperToken("");
    setHelperConnected(false);
    setHelperInfo(null);
    localStorage.removeItem("sovd_helper_token");
  }, []);

  // Connect to helper on demand — called by SessionTab when unlock is needed.
  // Returns the HelperInfo if successful, throws on failure.
  const ensureHelper = useCallback(async (): Promise<HelperInfo> => {
    if (helperConnected && helperInfo) return helperInfo;

    await invoke("set_security_helper", { url: helperUrl, token: helperToken });
    const info = await invoke<HelperInfo>("security_helper_info");
    setHelperInfo(info);

    // If OIDC mode and no token stored, prompt the user to sign in
    if (info.auth_mode === "oidc" && !helperToken) {
      setSettingsOpen(true);
      throw new Error("OIDC authentication required — please sign in via Settings");
    }

    // If helper switched to static mode but we have a stale OIDC JWT, reset to default
    if (info.auth_mode === "static" && helperToken.includes(".")) {
      const defaultToken = "dev-secret-123";
      setHelperToken(defaultToken);
      setOidcUser(null);
      localStorage.setItem("sovd_helper_token", defaultToken);
      await invoke("set_security_helper", { url: helperUrl, token: defaultToken });
    }

    setHelperConnected(true);
    localStorage.setItem("sovd_helper_url", helperUrl);
    localStorage.setItem("sovd_helper_token", helperToken);
    return info;
  }, [helperUrl, helperToken, helperConnected, helperInfo]);

  const toggleSettings = () => {
    setSettingsOpen(prev => {
      const next = !prev;
      localStorage.setItem("sovd_settings_open", String(next));
      return next;
    });
  };

  useEffect(() => {
    checkConnection();
  }, []);

  return (
    <LogContext.Provider value={{ logs, addLog, clearLogs }}>
      <div className="app">
        <header className="header">
          <h1>SOVD Explorer</h1>
          <div className="connection-status">
            <button className="settings-toggle" onClick={toggleSettings} title="Settings">
              ⚙
            </button>
            <span className={`status-dot ${connected ? "connected" : "disconnected"}`} />
            <span>{connected ? "Connected" : "Disconnected"}</span>
          </div>
        </header>

        {settingsOpen && (
          <div className="settings-overlay" onClick={toggleSettings}>
            <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
              <div className="settings-modal-header">
                <h2>Settings</h2>
                <button className="settings-close" onClick={toggleSettings}>×</button>
              </div>
              <div className="settings-modal-body">
                <div className="settings-group">
                  <label className="settings-label">SOVD Server</label>
                  <div className="settings-row">
                    <input
                      type="text"
                      value={serverUrl}
                      onChange={(e) => setServerUrl(e.target.value)}
                      placeholder="SOVD Server URL"
                      className="server-input"
                    />
                    <button onClick={checkConnection} className="connect-btn">
                      Connect
                    </button>
                  </div>
                </div>
                <div className="settings-group">
                  <label className="settings-label">Security Helper</label>
                  <div className="settings-row">
                    <input
                      type="text"
                      value={helperUrl}
                      onChange={(e) => { setHelperUrl(e.target.value); setHelperConnected(false); setHelperInfo(null); setOidcUser(null); }}
                      placeholder="Helper URL"
                      className="server-input"
                    />
                    <button onClick={probeHelper} className="connect-btn" title="Check helper auth mode">
                      Check
                    </button>
                  </div>
                  {helperInfo?.auth_mode === "oidc" && helperInfo.providers ? (
                    // OIDC mode: show sign-in buttons instead of password field
                    <div className="settings-row" style={{ flexDirection: "column", gap: "8px" }}>
                      {oidcUser ? (
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span className="helper-status-badge" title={`${helperInfo.name} v${helperInfo.version} (oidc)`}>
                            Helper OK (oidc)
                          </span>
                          <span style={{ fontSize: "12px", opacity: 0.8 }}>
                            {oidcUser.email} ({oidcUser.provider})
                          </span>
                          <button
                            onClick={oidcSignOut}
                            className="connect-btn"
                            style={{ marginLeft: "auto", fontSize: "12px" }}
                          >
                            Sign out
                          </button>
                        </div>
                      ) : (
                        helperInfo.providers.map((p) => (
                          <button
                            key={p.name}
                            onClick={() => oidcLogin(p.name)}
                            className="connect-btn"
                            disabled={oidcLoggingIn}
                            style={{ width: "100%" }}
                          >
                            {oidcLoggingIn ? "Signing in..." : `Sign in with ${p.name}`}
                          </button>
                        ))
                      )}
                    </div>
                  ) : (
                    // Static mode or not yet probed: show token password field
                    <div className="settings-row">
                      <input
                        type="password"
                        value={helperToken}
                        onChange={(e) => { setHelperToken(e.target.value); setHelperConnected(false); setHelperInfo(null); }}
                        placeholder="Token"
                        className="server-input"
                      />
                      {helperConnected && (
                        <span className="helper-status-badge" title={helperInfo ? `${helperInfo.name} v${helperInfo.version} (${helperInfo.auth_mode})` : ""}>
                          Helper OK ({helperInfo?.auth_mode || "?"})
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {error && <div className="error-banner">{error}</div>}

        <main className="main-content">
          <aside className="sidebar">
            <h2>Components</h2>
            {componentTree.length === 0 ? (
              <p className="no-data">No components found</p>
            ) : (
              <ul className="component-tree">
                {componentTree.map((node) => renderTreeNode(node))}
              </ul>
            )}
          </aside>

          <section className="content">
            {selectedComponent ? (
              <ComponentDetails
                componentId={selectedComponent}
                gatewayComponentId={gatewayContext}
                pathPrefix={selectedPathPrefix}
                ensureHelper={ensureHelper}
                allComponentIds={componentTree.flatMap(node =>
                  node.children.length > 0
                    ? node.children.map(c => c.component.id)
                    : [node.component.id]
                )}
              />
            ) : (
              <div className="placeholder">
                <p>Select a component to view details</p>
              </div>
            )}
          </section>
        </main>
      </div>
    </LogContext.Provider>
  );
}

// =============================================================================
// Component Details
// =============================================================================

interface ComponentDetailsProps {
  componentId: string;
  /** When set, this component is a sub-entity accessed through a gateway */
  gatewayComponentId?: string | null;
  /** Full path prefix from root gateway (e.g., "uds_gw/engine_ecu") */
  pathPrefix?: string | null;
  ensureHelper: () => Promise<HelperInfo>;
  allComponentIds: string[];
}

function ComponentDetails({ componentId, gatewayComponentId, pathPrefix, ensureHelper, allComponentIds }: ComponentDetailsProps) {
  const { addLog } = useLog();
  // When viewing a sub-entity, route API calls through the parent gateway
  const apiComponentId = gatewayComponentId || componentId;
  // Sub-entity path for routing data requests through /apps/{path}/data
  const appPath = gatewayComponentId && pathPrefix ? pathPrefix : null;
  // Prefix for filtering aggregated resources (faults, operations, IO controls)
  const paramPrefix = gatewayComponentId && pathPrefix ? pathPrefix + "/" : null;
  const [activeTab, setActiveTab] = useState<"data" | "faults" | "operations" | "iocontrol" | "software" | "logs">("data");
  const [parameterDefs, setParameterDefs] = useState<ParameterInfo[]>([]);
  const [parameterValues, setParameterValues] = useState<Map<string, DataResponse>>(new Map());
  const [previousParamValues, setPreviousParamValues] = useState<Map<string, DataResponse>>(new Map());
  const [faults, setFaults] = useState<FaultInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState<SessionMode>("default");
  const [security, setSecurity] = useState<SecurityState>("locked");
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [currentComponent, setCurrentComponent] = useState<string>("");

  // Monitoring state
  const [monitoring, setMonitoring] = useState(false);
  const [refreshRate, setRefreshRate] = useState(500);

  // Security toggle state
  const [securityBusy, setSecurityBusy] = useState(false);

  // ECU Info state
  const [ecuInfo, setEcuInfo] = useState<Record<string, string>>({});

  // Capabilities state (per SOVD §6.4)
  const [capabilities, setCapabilities] = useState<ComponentCapabilities | null>(null);

  // Clear state when component changes
  useEffect(() => {
    if (componentId !== currentComponent) {
      setParameterDefs([]);
      setParameterValues(new Map());
      setPreviousParamValues(new Map());
      setFaults([]);
      setSession("default");
      setSecurity("locked");
      setSessionError(null);
      setCurrentComponent(componentId);
      setMonitoring(false);
      setEcuInfo({});
      setCapabilities(null);
    }
  }, [componentId, currentComponent]);

  // Target path for routing session/security through gateway to specific child ECU
  const modeTarget = gatewayComponentId && pathPrefix ? pathPrefix : null;

  // Fetch session and security state independently so one failure doesn't block the other
  const fetchModes = useCallback(async () => {
    try {
      const sessionInfo = await invoke<SessionInfo>("get_session", { componentId: apiComponentId, target: modeTarget });
      setSession(parseSessionMode(sessionInfo.value));
      setSessionError(null);
    } catch (e) {
      console.error("Failed to fetch session:", e);
    }
    try {
      const securityInfo = await invoke<SecurityInfo>("get_security", { componentId: apiComponentId, target: modeTarget });
      setSecurity(parseSecurityState(securityInfo.value));
    } catch (e) {
      console.error("Failed to fetch security:", e);
    }
  }, [apiComponentId, modeTarget]);

  // Fetch ECU identification info
  const fetchEcuInfo = useCallback(async () => {
    try {
      const info = await invoke<Record<string, string>>("get_ecu_info", {
        componentId: apiComponentId,
        prefix: appPath || null,
      });
      setEcuInfo(info);
    } catch (e) {
      console.error("Failed to fetch ECU info:", e);
    }
  }, [apiComponentId, appPath]);

  // Write parameter handler
  const handleWriteParameter = useCallback(async (parameterId: string, value: unknown) => {
    try {
      await invoke("write_parameter", { componentId: apiComponentId, dataId: parameterId, value, appPath: appPath });
      addLog({
        type: "write",
        component: componentId,
        action: `Write ${parameterId}`,
        details: `Value: ${JSON.stringify(value)}`,
        success: true,
      });
    } catch (e) {
      addLog({
        type: "error",
        component: componentId,
        action: `Write ${parameterId}`,
        details: String(e),
        success: false,
      });
      throw e;
    }
  }, [apiComponentId, addLog]);

  // Change session
  const changeSession = async (newSession: SessionMode) => {
    try {
      setSessionError(null);
      const result = await invoke<SessionInfo>("set_session", {
        componentId: apiComponentId,
        session: newSession,
        target: modeTarget,
      });
      setSession(parseSessionMode(result.value));
      // Session change may affect security — refresh both
      await fetchModes();
      addLog({
        type: "operation",
        component: componentId,
        action: "Set Session",
        details: `Changed to ${newSession}`,
        success: true,
      });
      // Refresh data after session change
      if (activeTab === "data") {
        refreshValues();
      }
    } catch (e) {
      setSessionError(`Session change failed: ${e}`);
      addLog({
        type: "error",
        component: componentId,
        action: "Set Session",
        details: String(e),
        success: false,
      });
    }
  };

  // Change security state via dropdown
  const changeSecurityState = useCallback(async (target: SecurityState) => {
    if (target === security) return; // already in target state

    setSecurityBusy(true);
    setSessionError(null);

    if (target === "unlocked") {
      // Unlock: need extended/engineering session + helper
      if (session === "default") {
        setSessionError("Switch to Extended or Engineering session before unlocking");
        setSecurityBusy(false);
        return;
      }
      try {
        const info = await ensureHelper();
        if (!info.supported_ecus.includes(componentId)) {
          throw new Error(`ECU '${componentId}' not supported by helper. Supported: ${info.supported_ecus.join(", ")}`);
        }

        const seedResult = await invoke<SecurityInfo>("request_security_seed", {
          componentId: apiComponentId,
          level: 1,
          target: modeTarget,
        });
        if (!seedResult.seed) throw new Error("ECU returned empty seed");

        const seedHex = seedResult.seed
          .split(/\s+/)
          .map((s) => {
            const n = parseInt(s.replace(/^0x/i, ""), 16);
            return isNaN(n) ? "" : n.toString(16).padStart(2, "0");
          })
          .join("");

        const calcResult = await invoke<HelperResult>("security_helper_calculate", {
          seed: seedHex,
          level: 1,
          componentId,
          vin: ecuInfo.vin || null,
          logicalAddress: null,
          partNumber: ecuInfo.part_number || null,
          hwVersion: ecuInfo.hw_version || null,
          swVersion: ecuInfo.ecu_sw_version || null,
          supplier: ecuInfo.supplier || null,
        });
        if (!calcResult.success || !calcResult.key) {
          throw new Error(calcResult.error || "Helper returned no key");
        }

        await invoke<SecurityInfo>("send_security_key", {
          componentId: apiComponentId,
          level: 1,
          key: calcResult.key,
          target: modeTarget,
        });

        addLog({
          type: "operation",
          component: componentId,
          action: "Security Unlock",
          details: `${componentId} (via helper)`,
          success: true,
        });
      } catch (e) {
        setSessionError(`Unlock failed: ${e}`);
        addLog({
          type: "error",
          component: componentId,
          action: "Security Unlock",
          details: String(e),
          success: false,
        });
      }
    } else {
      // Lock: cycle session to default and back to re-lock security
      const currentSession = session;
      try {
        await invoke<SessionInfo>("set_session", { componentId: apiComponentId, session: "default", target: modeTarget });
        if (currentSession !== "default") {
          await invoke<SessionInfo>("set_session", { componentId: apiComponentId, session: currentSession, target: modeTarget });
        }
        addLog({
          type: "operation",
          component: componentId,
          action: "Security Lock",
          details: `Re-locked (session cycled via default)`,
          success: true,
        });
      } catch (e) {
        setSessionError(`Lock failed: ${e}`);
        addLog({
          type: "error",
          component: componentId,
          action: "Security Lock",
          details: String(e),
          success: false,
        });
      }
    }

    await fetchModes();
    setSecurityBusy(false);
  }, [security, session, apiComponentId, ecuInfo, ensureHelper, fetchModes, addLog]);

  // Fetch parameter definitions
  const fetchParameterDefs = useCallback(async (): Promise<ParameterInfo[]> => {
    try {
      const params = await invoke<ParameterInfo[]>("list_parameters", {
        componentId: apiComponentId,
        appPath: appPath,
      });
      setParameterDefs(params);
      return params;
    } catch (e) {
      console.error("Failed to fetch parameters:", e);
    }
    return [];
  }, [apiComponentId, appPath]);

  // Fetch values for parameters
  const fetchValuesForParams = useCallback(
    async (params: ParameterInfo[], trackChanges: boolean = false) => {
      if (params.length === 0) return;

      setLoading(true);

      // Store previous values for change tracking
      if (trackChanges) {
        setPreviousParamValues(new Map(parameterValues));
      }

      const values = new Map<string, DataResponse>();
      let successCount = 0;
      let errorCount = 0;

      for (const param of params) {
        try {
          const data = await invoke<DataResponse>("read_parameter", {
            componentId: apiComponentId,
            parameterId: param.id,
            appPath: appPath,
          });
          values.set(param.id, data);
          successCount++;
        } catch (e) {
          values.set(param.id, {
            value: null,
            raw: undefined,
          });
          errorCount++;
        }
      }

      // Log summary of read operation (not every individual read)
      if (!trackChanges) {
        addLog({
          type: "read",
          component: componentId,
          action: "Read Parameters",
          details: `${successCount} OK, ${errorCount} failed`,
          success: errorCount === 0,
        });
      }

      setParameterValues(values);
      setLoading(false);
    },
    [apiComponentId, appPath, parameterValues, addLog]
  );

  // Refresh values
  const refreshValues = useCallback(() => {
    fetchValuesForParams(parameterDefs, monitoring);
  }, [fetchValuesForParams, parameterDefs, monitoring]);

  // Monitoring effect - auto-refresh at interval
  useEffect(() => {
    if (!monitoring || activeTab !== "data") return;

    const interval = setInterval(() => {
      fetchValuesForParams(parameterDefs, true);
    }, refreshRate);

    return () => clearInterval(interval);
  }, [monitoring, refreshRate, parameterDefs, fetchValuesForParams, activeTab]);

  // Fetch faults
  const fetchFaults = useCallback(async () => {
    setLoading(true);
    try {
      let faultList = await invoke<FaultInfo[]>("list_faults", { componentId: apiComponentId });
      if (paramPrefix) {
        faultList = faultList.filter(f => f.id.startsWith(paramPrefix));
      }
      setFaults(faultList);
    } catch (e) {
      console.error("Failed to fetch faults:", e);
    }
    setLoading(false);
  }, [apiComponentId, paramPrefix]);

  // Fetch capabilities (SOVD §6.4) on component change
  const fetchCapabilities = useCallback(async () => {
    try {
      if (gatewayComponentId && pathPrefix) {
        // Sub-entity: fetch via get_app_detail
        const detail = await invoke<AppInfo>("get_app_detail", {
          componentId: gatewayComponentId,
          appId: pathPrefix,
        });
        if (detail.capabilities) setCapabilities(detail.capabilities);
      } else {
        // Root component: fetch via get_component
        const detail = await invoke<Component>("get_component", { componentId });
        if (detail.capabilities) setCapabilities(detail.capabilities);
      }
    } catch (e) {
      console.warn("Failed to fetch capabilities:", e);
    }
  }, [componentId, gatewayComponentId, pathPrefix]);

  // Reset to first available tab if current tab becomes unavailable
  useEffect(() => {
    if (!capabilities) return;
    const tabCaps: Record<string, boolean | undefined> = {
      data: capabilities.read_data,
      faults: capabilities.faults,
      operations: capabilities.operations,
      iocontrol: capabilities.io_control,
      software: capabilities.software_update,
      logs: capabilities.logs,
    };
    if (tabCaps[activeTab] === false) {
      const firstAvailable = Object.entries(tabCaps).find(([, v]) => v !== false);
      if (firstAvailable) setActiveTab(firstAvailable[0] as typeof activeTab);
    }
  }, [capabilities]);

  // Load data when component changes
  useEffect(() => {
    const loadComponentData = async () => {
      fetchCapabilities();
      await fetchModes();
      await fetchEcuInfo();
      if (activeTab === "data") {
        const defs = await fetchParameterDefs();
        await fetchValuesForParams(defs);
      } else if (activeTab === "faults") {
        await fetchFaults();
      }
    };
    loadComponentData();
  }, [componentId]);

  // Handle tab changes
  useEffect(() => {
    const loadTabData = async () => {
      if (activeTab === "data") {
        if (parameterDefs.length === 0) {
          const defs = await fetchParameterDefs();
          await fetchValuesForParams(defs);
        } else {
          await fetchValuesForParams(parameterDefs);
        }
      } else if (activeTab === "faults") {
        await fetchFaults();
      }
    };
    if (currentComponent === componentId) {
      loadTabData();
    }
  }, [activeTab]);

  // Build ECU info grid from all available fields
  const ecuFields: [string, string][] = [
    ["VIN", ecuInfo.vin],
    ["Serial", ecuInfo.ecu_serial],
    ["SW Version", ecuInfo.ecu_sw_version],
    ["HW Version", ecuInfo.hw_version],
    ["Part Number", ecuInfo.part_number],
    ["Supplier", ecuInfo.supplier],
    ["Supplier SW", ecuInfo.supplier_sw_version],
    ["SW Number", ecuInfo.sw_number],
    ["HW Number", ecuInfo.hw_number],
    ["Mfg Date", ecuInfo.mfg_date],
    ["Prog Date", ecuInfo.programming_date],
  ].filter((f): f is [string, string] => !!f[1]);

  return (
    <div className="component-details">
      <div className="component-header">
        <div>
          <div className="component-heading">
            <h2>{ecuInfo.system_name || componentId}</h2>
            {ecuInfo.system_name && <span className="component-id-tag">{componentId}</span>}
          </div>
          {ecuFields.length > 0 && (
            <div className="ecu-info-grid">
              {ecuFields.map(([label, value]) => (
                <div key={label} className="ecu-info-cell">
                  <span className="ecu-info-label">{label}</span>
                  <span className="ecu-info-value">{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        {(capabilities?.sessions !== false) && (
          <div className="status-indicators">
            <select
              className={`session-select-header ${session}`}
              value={session}
              onChange={(e) => changeSession(e.target.value as SessionMode)}
            >
              {SESSION_MODES.map((mode) => (
                <option key={mode} value={mode}>{sessionModeLabel(mode)}</option>
              ))}
            </select>
            {capabilities?.security !== false && (
              <select
                className={`security-select ${security}`}
                value={security}
                onChange={(e) => changeSecurityState(e.target.value as SecurityState)}
                disabled={securityBusy}
              >
                <option value="locked">Locked</option>
                <option value="unlocked">Unlocked</option>
              </select>
            )}
          </div>
        )}
      </div>

      {sessionError && <div className="session-error">{sessionError}</div>}

      <div className="tabs">
        {capabilities?.read_data !== false && (
          <button
            className={`tab ${activeTab === "data" ? "active" : ""}`}
            onClick={() => setActiveTab("data")}
          >
            Data
          </button>
        )}
        {capabilities?.faults !== false && (
          <button
            className={`tab ${activeTab === "faults" ? "active" : ""}`}
            onClick={() => setActiveTab("faults")}
          >
            Faults
          </button>
        )}
        {capabilities?.operations !== false && (
          <button
            className={`tab ${activeTab === "operations" ? "active" : ""}`}
            onClick={() => setActiveTab("operations")}
          >
            Operations
          </button>
        )}
        {capabilities?.io_control !== false && (
          <button
            className={`tab ${activeTab === "iocontrol" ? "active" : ""}`}
            onClick={() => setActiveTab("iocontrol")}
          >
            I/O Control
          </button>
        )}
        {capabilities?.software_update !== false && (
          <button
            className={`tab ${activeTab === "software" ? "active" : ""}`}
            onClick={() => setActiveTab("software")}
          >
            Software
          </button>
        )}
        {capabilities?.logs !== false && (
          <button
            className={`tab ${activeTab === "logs" ? "active" : ""}`}
            onClick={() => setActiveTab("logs")}
          >
            Logs
          </button>
        )}
        {activeTab === "data" && (
          <button className="refresh-btn" onClick={refreshValues} disabled={loading || monitoring}>
            {monitoring ? "Monitoring..." : loading ? "Loading..." : "Refresh"}
          </button>
        )}
      </div>

      <div className="tab-content">
        {activeTab === "data" ? (
          <DataTab
            parameters={parameterDefs}
            values={parameterValues}
            loading={loading}
            componentId={componentId}
            paramPrefix={paramPrefix}
            onRefresh={refreshValues}
            onWriteParameter={handleWriteParameter}
            monitoring={monitoring}
            onMonitoringChange={setMonitoring}
            refreshRate={refreshRate}
            onRefreshRateChange={setRefreshRate}
            previousValues={previousParamValues}
          />
        ) : activeTab === "faults" ? (
          <FaultsTab faults={faults} loading={loading} />
        ) : activeTab === "operations" ? (
          <OperationsTab
            componentId={apiComponentId}
            session={session}
            security={security}
            paramPrefix={paramPrefix}
          />
        ) : activeTab === "iocontrol" ? (
          <IoControlTab componentId={apiComponentId} session={session} security={security} paramPrefix={paramPrefix} />
        ) : activeTab === "software" ? (
          <SoftwareTab componentId={componentId} gatewayComponentId={gatewayComponentId} modeTarget={modeTarget} apiComponentId={apiComponentId} session={session} onUpdateComplete={async () => { await fetchModes(); await fetchEcuInfo(); }} allComponentIds={allComponentIds} />
        ) : activeTab === "logs" ? (
          <LogsTab />
        ) : null}
      </div>
    </div>
  );
}

// =============================================================================
// Data Tab
// =============================================================================

interface DataTabProps {
  parameters: ParameterInfo[];
  values: Map<string, DataResponse>;
  loading: boolean;
  componentId: string;
  /** Active prefix filter (e.g., "uds_gw/engine_ecu/") — used to compute relative source */
  paramPrefix?: string | null;
  onRefresh: () => void;
  onWriteParameter?: (parameterId: string, value: unknown) => Promise<void>;
  monitoring?: boolean;
  onMonitoringChange?: (enabled: boolean) => void;
  refreshRate?: number;
  onRefreshRateChange?: (rate: number) => void;
  previousValues?: Map<string, DataResponse>;
}

function DataTab({
  parameters,
  values,
  loading,
  // componentId is in props for future use
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  componentId: _componentId,
  paramPrefix,
  onRefresh,
  onWriteParameter,
  monitoring = false,
  onMonitoringChange,
  refreshRate = 500,
  onRefreshRateChange,
  previousValues
}: DataTabProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [editingParam, setEditingParam] = useState<string | null>(null);
  const [editValue, setEditValue] = useState<string>("");
  const [writeError, setWriteError] = useState<string | null>(null);
  const [writing, setWriting] = useState(false);

  // Filter parameters based on search term
  const filteredParameters = parameters.filter(p =>
    p.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
    p.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    p.did.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (parameters.length === 0) {
    return <p className="no-data">No parameters available</p>;
  }

  // Strip the active prefix from param IDs to get the relative ID
  const relativeId = (paramId: string): string => {
    if (paramPrefix && paramId.startsWith(paramPrefix)) {
      return paramId.substring(paramPrefix.length);
    }
    return paramId;
  };

  // Check if any parameter has a source prefix relative to the current view
  const hasSourcePrefix = parameters.some((p) => relativeId(p.id).includes("/"));

  // Extract source from relative ID — everything before the last "/"
  // e.g., for gateway view: "uds_gw/engine_ecu/coolant_temp" -> "uds_gw/engine_ecu"
  // e.g., for uds_gw view (prefix="uds_gw/"): "engine_ecu/coolant_temp" -> "engine_ecu"
  // e.g., for engine_ecu view (prefix="uds_gw/engine_ecu/"): "coolant_temp" -> null
  const getSource = (paramId: string): string | null => {
    const rel = relativeId(paramId);
    const slashIndex = rel.lastIndexOf("/");
    if (slashIndex > 0) {
      return rel.substring(0, slashIndex);
    }
    return null;
  };

  // Format source path for display (e.g., "uds_gw/engine_ecu" -> "UDS GW / Engine ECU")
  const formatSource = (source: string): string => {
    return source
      .split("/")
      .map(seg => seg.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()).replace(/Ecu/g, "ECU").replace(/Gw/g, "GW"))
      .join(" / ");
  };

  const formatValue = (val: DataResponse | undefined, def: ParameterInfo): string => {
    if (!val) return loading ? "..." : "-";
    if (val.value === null || val.value === undefined) return "-";

    // If converted, show the value directly
    if (val.converted && val.value !== null) {
      return String(val.value);
    }

    // Raw string value
    const raw = String(val.value);

    // Try to detect ASCII strings (VIN, etc.)
    if (def.data_type === "ascii" || def.data_type === "string" || def.name?.includes("VIN")) {
      return hexToAscii(raw);
    }

    // For numeric types, show decimal value
    if (raw.length <= 8 && /^[0-9a-fA-F]+$/.test(raw)) {
      const num = parseInt(raw, 16);
      if (!isNaN(num)) {
        return num.toString();
      }
    }

    return raw;
  };

  // Highlight matching text in search results
  const highlightMatch = (text: string): React.ReactNode => {
    if (!searchTerm || !text) return text;
    const index = text.toLowerCase().indexOf(searchTerm.toLowerCase());
    if (index === -1) return text;
    return (
      <>
        {text.substring(0, index)}
        <span className="search-highlight">{text.substring(index, index + searchTerm.length)}</span>
        {text.substring(index + searchTerm.length)}
      </>
    );
  };

  // Check if value changed since last read (for monitoring)
  const hasValueChanged = (paramId: string): boolean => {
    if (!previousValues) return false;
    const current = values.get(paramId);
    const previous = previousValues.get(paramId);
    if (!current || !previous) return false;
    return JSON.stringify(current.value) !== JSON.stringify(previous.value);
  };

  // Get trend indicator for numeric values
  const getTrendIndicator = (paramId: string): string | null => {
    if (!previousValues) return null;
    const current = values.get(paramId);
    const previous = previousValues.get(paramId);
    if (!current || !previous) return null;
    const currNum = typeof current.value === 'number' ? current.value : parseFloat(String(current.value));
    const prevNum = typeof previous.value === 'number' ? previous.value : parseFloat(String(previous.value));
    if (isNaN(currNum) || isNaN(prevNum)) return null;
    if (currNum > prevNum) return "▲";
    if (currNum < prevNum) return "▼";
    return null;
  };

  // Handle write parameter
  const handleStartEdit = (paramId: string, currentValue: DataResponse | undefined) => {
    setEditingParam(paramId);
    setEditValue(currentValue?.value !== undefined ? String(currentValue.value) : "");
    setWriteError(null);
  };

  const handleCancelEdit = () => {
    setEditingParam(null);
    setEditValue("");
    setWriteError(null);
  };

  const handleWriteParameter = async () => {
    if (!editingParam || !onWriteParameter) return;
    setWriting(true);
    setWriteError(null);
    try {
      // Use the parameter's data_type to determine how to encode the value
      const param = parameters.find((p) => p.id === editingParam);
      const dataType = param?.data_type?.toLowerCase();
      let parsedValue: unknown = editValue;

      if (dataType === "string") {
        // String DIDs: always send as string, even if value looks numeric
        parsedValue = editValue;
      } else if (dataType?.startsWith("uint") || dataType?.startsWith("int")) {
        // Integer DIDs: parse as number
        if (/^\d+$/.test(editValue)) {
          parsedValue = parseInt(editValue, 10);
        } else if (/^\d+\.\d+$/.test(editValue)) {
          parsedValue = parseFloat(editValue);
        }
      } else if (dataType?.startsWith("float")) {
        // Float DIDs: parse as float
        const n = parseFloat(editValue);
        if (!isNaN(n)) parsedValue = n;
      }

      await onWriteParameter(editingParam, parsedValue);
      onRefresh();
    } catch (e) {
      setWriteError(String(e));
    } finally {
      setEditingParam(null);
      setEditValue("");
      setWriting(false);
    }
  };

  return (
    <div className="data-tab">
      {/* Search and Monitoring Controls */}
      <div className="data-controls">
        <div className="search-container">
          <input
            type="text"
            placeholder="Search by name, ID, or DID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
          {searchTerm && (
            <button className="search-clear" onClick={() => setSearchTerm("")}>×</button>
          )}
        </div>
        <span className="param-count">
          {filteredParameters.length} of {parameters.length} parameters
        </span>
        {onMonitoringChange && (
          <div className="monitoring-controls">
            <label className="monitor-toggle">
              <input
                type="checkbox"
                checked={monitoring}
                onChange={(e) => onMonitoringChange(e.target.checked)}
              />
              <span className="monitor-label">Monitor</span>
            </label>
            {monitoring && onRefreshRateChange && (
              <select
                value={refreshRate}
                onChange={(e) => onRefreshRateChange(Number(e.target.value))}
                className="refresh-rate-select"
              >
                <option value={100}>100ms</option>
                <option value={250}>250ms</option>
                <option value={500}>500ms</option>
                <option value={1000}>1s</option>
                <option value={2000}>2s</option>
              </select>
            )}
          </div>
        )}
      </div>

      {/* Write Error Display */}
      {writeError && (
        <div className="write-error">
          Write failed: {writeError}
          <button className="dismiss-error" onClick={() => setWriteError(null)}>×</button>
        </div>
      )}

      {filteredParameters.length === 0 ? (
        <p className="no-data">No parameters match "{searchTerm}"</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              {hasSourcePrefix && <th>Source</th>}
              <th>DID</th>
              <th>Name</th>
              <th>Value</th>
              <th>Raw (hex)</th>
              <th>Unit</th>
              {onWriteParameter && <th>Actions</th>}
            </tr>
          </thead>
          <tbody>
            {filteredParameters.map((param) => {
              const val = values.get(param.id);
              const source = getSource(param.id);
              const changed = hasValueChanged(param.id);
              const trend = getTrendIndicator(param.id);
              const isEditing = editingParam === param.id;

              return (
                <tr key={param.id} className={changed ? "value-changed" : ""}>
                  {hasSourcePrefix && (
                    <td className="source-cell">
                      {source && <span className="source-badge">{formatSource(source)}</span>}
                    </td>
                  )}
                  <td className="did-cell">{highlightMatch(param.did)}</td>
                  <td>{highlightMatch(param.name || param.id)}</td>
                  <td className="value-cell">
                    {isEditing ? (
                      <div className="edit-value-container">
                        <input
                          type="text"
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          className="edit-value-input"
                          autoFocus
                          onKeyDown={(e) => {
                            if (e.key === "Enter") handleWriteParameter();
                            if (e.key === "Escape") handleCancelEdit();
                          }}
                        />
                        <button
                          className="edit-btn save"
                          onClick={handleWriteParameter}
                          disabled={writing}
                        >
                          {writing ? "..." : "✓"}
                        </button>
                        <button className="edit-btn cancel" onClick={handleCancelEdit}>×</button>
                      </div>
                    ) : (
                      <>
                        {trend && <span className={`trend-indicator ${trend === "▲" ? "up" : "down"}`}>{trend}</span>}
                        {formatValue(val, param)}
                      </>
                    )}
                  </td>
                  <td className="raw-cell">{val?.raw || "-"}</td>
                  <td>{param.unit || val?.unit || "-"}</td>
                  {onWriteParameter && (
                    <td className="actions-cell">
                      {!isEditing && param.writable && (
                        <button
                          className="edit-param-btn"
                          onClick={() => handleStartEdit(param.id, val)}
                          title="Edit parameter"
                        >
                          ✎
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// =============================================================================
// Faults Tab
// =============================================================================

interface FaultsTabProps {
  faults: FaultInfo[];
  loading: boolean;
}

function FaultsTab({ faults, loading }: FaultsTabProps) {
  if (loading) {
    return <p className="no-data">Loading...</p>;
  }

  if (faults.length === 0) {
    return <p className="no-data">No faults stored</p>;
  }

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>DTC Code</th>
          <th>Message</th>
          <th>Category</th>
          <th>Severity</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {faults.map((fault) => (
          <tr key={fault.id} className={fault.active ? "fault-active" : ""}>
            <td className="dtc-cell">{fault.code || fault.id}</td>
            <td>{fault.message || "-"}</td>
            <td>{fault.category || "-"}</td>
            <td className={`severity-${fault.severity}`}>{fault.severity || "-"}</td>
            <td>
              {fault.active ? (
                <span className="status-tag active">Active</span>
              ) : (
                <span className="status-tag inactive">Inactive</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// =============================================================================
// Operations Tab
// =============================================================================

interface OperationsTabProps {
  componentId: string;
  session: SessionMode;
  security: SecurityState;
  paramPrefix?: string | null;
}

function OperationsTab({ componentId, session, security, paramPrefix }: OperationsTabProps) {
  const [operations, setOperations] = useState<OperationInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [executingOp, setExecutingOp] = useState<string | null>(null);
  const [results, setResults] = useState<Map<string, OperationResponse>>(new Map());

  const fetchOperations = useCallback(async () => {
    setLoading(true);
    try {
      let ops = await invoke<OperationInfo[]>("list_operations", { componentId });
      if (paramPrefix) {
        ops = ops.filter(op => op.id.startsWith(paramPrefix));
      }
      setOperations(ops);
    } catch (e) {
      console.error("Failed to fetch operations:", e);
    }
    setLoading(false);
  }, [componentId, paramPrefix]);

  useEffect(() => {
    fetchOperations();
  }, [fetchOperations]);

  const executeOperation = async (opId: string, action: "start" | "stop" | "result") => {
    setExecutingOp(opId);
    try {
      const response = await invoke<OperationResponse>("execute_operation", {
        componentId,
        operationId: opId,
        action,
      });
      setResults(new Map(results.set(opId, response)));
    } catch (e) {
      setResults(
        new Map(
          results.set(opId, {
            operation_id: opId,
            action,
            status: "error",
            error: String(e),
            timestamp: Date.now(),
          })
        )
      );
    }
    setExecutingOp(null);
  };

  if (loading) {
    return <p className="no-data">Loading operations...</p>;
  }

  if (operations.length === 0) {
    return <p className="no-data">No operations available</p>;
  }

  const formatResult = (result: OperationResponse | undefined): string => {
    if (!result) return "-";
    if (result.error) return `Error: ${result.error}`;
    if (result.result_data) return result.result_data;
    return result.status;
  };

  const isExtendedSession = session === "extended" || session === "engineering";
  const isSecurityUnlocked = security === "unlocked";

  return (
    <div className="operations-tab">
      {!isExtendedSession && (
        <div className="session-warning">
          Some operations require Extended or Engineering session. Currently in {session} session.
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Description</th>
            <th>Requires</th>
            <th>Actions</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {operations.map((op) => {
            const result = results.get(op.id);
            const isExecuting = executingOp === op.id;
            const needsSecurity = op.requires_security;
            const opBlocked = needsSecurity && (!isExtendedSession || !isSecurityUnlocked);

            return (
              <tr key={op.id} className={`${result?.error ? "row-error" : ""} ${opBlocked ? "security-required" : ""}`}>
                <td>{op.name}</td>
                <td className="description-cell">{op.description || "-"}</td>
                <td className="security-cell">
                  {needsSecurity ? (
                    <span className="prereq-pills">
                      <span className={`prereq-pill session-extended ${isExtendedSession ? "" : "unmet"}`}>Extended</span>
                      <span className={`prereq-pill security-unlock ${isSecurityUnlocked ? "" : "unmet"}`}>Unlock</span>
                    </span>
                  ) : (
                    <span className="prereq-pill no-security">None</span>
                  )}
                </td>
                <td className="actions-cell">
                  <button
                    className="op-btn start"
                    onClick={() => executeOperation(op.id, "start")}
                    disabled={isExecuting || opBlocked}
                  >
                    {isExecuting ? "..." : "Start"}
                  </button>
                  <button
                    className="op-btn result"
                    onClick={() => executeOperation(op.id, "result")}
                    disabled={isExecuting || opBlocked}
                  >
                    Result
                  </button>
                  <button
                    className="op-btn stop"
                    onClick={() => executeOperation(op.id, "stop")}
                    disabled={isExecuting || opBlocked}
                  >
                    Stop
                  </button>
                </td>
                <td
                  className={`result-cell ${
                    result?.error ? "error" : result?.status === "completed" ? "success" : ""
                  }`}
                >
                  {formatResult(result)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// =============================================================================
// Logs Tab
// =============================================================================

// =============================================================================
// Logs Tab
// =============================================================================

function LogsTab() {
  const { logs, clearLogs } = useLog();
  const [logFilter, setLogFilter] = useState<string>("all");

  const filteredLogs = logs.filter(log =>
    logFilter === "all" || log.type === logFilter
  );

  const exportLogs = async (format: "json" | "csv" | "txt") => {
    try {
      await invoke("export_logs", { logs, format });
    } catch (e) {
      console.error("Failed to export logs:", e);
    }
  };

  return (
    <div className="logs-tab">
      <div className="logs-toolbar">
        <select
          value={logFilter}
          onChange={(e) => setLogFilter(e.target.value)}
          className="log-filter-select"
        >
          <option value="all">All</option>
          <option value="read">Read</option>
          <option value="write">Write</option>
          <option value="operation">Operation</option>
          <option value="error">Error</option>
          <option value="info">Info</option>
        </select>
        <button className="log-export-btn" onClick={() => exportLogs("json")} title="Export as JSON">
          JSON
        </button>
        <button className="log-export-btn" onClick={() => exportLogs("csv")} title="Export as CSV">
          CSV
        </button>
        <button className="log-export-btn" onClick={() => exportLogs("txt")} title="Export as Text">
          TXT
        </button>
        <button className="log-clear-btn" onClick={clearLogs} title="Clear logs">
          Clear
        </button>
        <span className="logs-count">{logs.length} entries</span>
      </div>

      {filteredLogs.length === 0 ? (
        <p className="log-empty">No log entries{logFilter !== "all" ? ` matching "${logFilter}"` : ""}</p>
      ) : (
        <table className="log-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Type</th>
              <th>Component</th>
              <th>Action</th>
              <th>Details</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.map((log, idx) => (
              <tr key={idx} className={`log-row ${log.type} ${log.success ? "" : "failed"}`}>
                <td className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</td>
                <td className="log-type">
                  <span className={`log-type-badge ${log.type}`}>{log.type}</span>
                </td>
                <td className="log-component">{log.component}</td>
                <td className="log-action">{log.action}</td>
                <td className="log-details">{log.details}</td>
                <td className="log-status">
                  {log.success ? <span className="log-success">OK</span> : <span className="log-fail">FAIL</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// =============================================================================
// I/O Control Tab
// =============================================================================

interface IoControlTabProps {
  componentId: string;
  session: SessionMode;
  security: SecurityState;
  paramPrefix?: string | null;
}

interface IoControlInfo {
  id: string;
  name: string;
  current_state?: string;
  value?: unknown;
  default_value?: unknown;
  allowed?: unknown[];
  controllable: boolean;
  controlled_by_tester?: boolean;
  frozen?: boolean;
  requires_security?: boolean;
  security_level?: number;
}

interface IoControlResponse {
  success: boolean;
  state: string;
  message?: string;
  frozen?: boolean;
  new_value?: string;
  value?: unknown;
}

function IoControlTab({ componentId, session, security, paramPrefix }: IoControlTabProps) {
  const [controls, setControls] = useState<IoControlInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState<string | null>(null);
  const [results, setResults] = useState<Map<string, IoControlResponse>>(new Map());
  const [adjustValue, setAdjustValue] = useState<Map<string, string>>(new Map());
  const [error, setError] = useState<string | null>(null);
  const [notSupported, setNotSupported] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // Track locally-known state from control responses so auto-refresh doesn't discard it
  const controlOverrides = useRef<Map<string, { value?: unknown; current_state?: string; frozen?: boolean; controlled_by_tester?: boolean }>>(new Map());

  // Fetch available I/O controls (full load with loading indicator)
  const fetchControls = useCallback(async () => {
    setLoading(true);
    setNotSupported(false);
    try {
      let controlList = await invoke<IoControlInfo[]>("list_io_controls", { componentId });
      if (paramPrefix) {
        controlList = controlList.filter(c => c.id.startsWith(paramPrefix));
      }
      setControls(controlList);
    } catch (e) {
      console.error("I/O controls not available:", e);
      setControls([]);
      setNotSupported(true);
    }
    setLoading(false);
  }, [componentId, paramPrefix]);

  // Silent refresh (no loading flash, for polling)
  // Merges server data with locally-known overrides from recent control responses
  const refreshControls = useCallback(async () => {
    try {
      let controlList = await invoke<IoControlInfo[]>("list_io_controls", { componentId });
      if (paramPrefix) {
        controlList = controlList.filter(c => c.id.startsWith(paramPrefix));
      }
      const overrides = controlOverrides.current;
      if (overrides.size > 0) {
        setControls(controlList.map(c => {
          const ov = overrides.get(c.id);
          if (!ov) return c;
          // If the server now reports the same state, the override is no longer needed
          if (c.frozen === ov.frozen && c.controlled_by_tester === ov.controlled_by_tester) {
            overrides.delete(c.id);
            return c;
          }
          return { ...c, ...ov };
        }));
      } else {
        setControls(controlList);
      }
    } catch {
      // Silently ignore polling errors
    }
  }, [componentId, paramPrefix]);

  // Initial fetch
  useEffect(() => {
    fetchControls();
  }, [fetchControls]);

  // Auto-refresh polling
  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    if (autoRefresh && !notSupported) {
      intervalRef.current = setInterval(refreshControls, 2000);
    }
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [autoRefresh, notSupported, refreshControls]);

  // Execute I/O control action
  const executeControl = async (controlId: string, action: string, value?: unknown) => {
    setExecuting(controlId);
    setError(null);
    try {
      const response = await invoke<IoControlResponse>("io_control", {
        componentId,
        dataId: controlId,
        action,
        value: value ?? null,
      });
      setResults(new Map(results.set(controlId, response)));
      // Update local control state immediately from the response
      if (response.success) {
        const override: { value?: unknown; current_state?: string; frozen?: boolean; controlled_by_tester?: boolean } = {};
        if (response.value != null || response.new_value != null) {
          override.value = response.value ?? response.new_value;
        }
        if (response.new_value != null) {
          override.current_state = response.new_value;
        }
        if (response.frozen != null) {
          override.frozen = response.frozen;
        }
        if (response.state === "controlled") {
          override.controlled_by_tester = true;
        } else if (response.state === "released") {
          override.controlled_by_tester = false;
        }
        controlOverrides.current.set(controlId, override);
        setControls(prev => prev.map(c => {
          if (c.id !== controlId) return c;
          return { ...c, ...override };
        }));
      }
    } catch (e) {
      setResults(new Map(results.set(controlId, {
        success: false,
        state: "error",
        message: String(e),
      })));
      setError(String(e));
    }
    setExecuting(null);
  };

  const isExtendedSession = session === "extended" || session === "engineering";
  const isSecurityUnlocked = security === "unlocked";

  if (loading) {
    return <p className="no-data">Loading I/O controls...</p>;
  }

  if (notSupported) {
    return <p className="no-data">I/O Control (InputOutputControlByIdentifier) is not supported by this ECU</p>;
  }

  if (controls.length === 0) {
    return <p className="no-data">No I/O controls defined for this component</p>;
  }

  const hasSecuredControls = controls.some(c => c.requires_security);

  return (
    <div className="io-control-tab">
      {!isExtendedSession && (
        <div className="session-warning">
          Some I/O controls require Extended or Engineering session. Currently in {session} session.
        </div>
      )}

      {isExtendedSession && !isSecurityUnlocked && hasSecuredControls && (
        <div className="session-warning">
          Some I/O controls require security unlock.
        </div>
      )}

      {error && (
        <div className="io-control-error">
          {error}
          <button className="dismiss-error" onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className="io-control-toolbar">
        <label className="auto-refresh-toggle">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          Auto-refresh
        </label>
        <button className="op-btn io-reset" onClick={fetchControls} title="Refresh now">
          Refresh
        </button>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Control</th>
            <th>Requires</th>
            <th>Current State</th>
            <th>Actions</th>
            <th>Result</th>
          </tr>
        </thead>
        <tbody>
          {controls.map((control) => {
            const result = results.get(control.id);
            const isExecutingThis = executing === control.id;
            const currentAdjustValue = adjustValue.get(control.id) || "";
            const hasAllowed = control.allowed && control.allowed.length > 0;
            const securityBlocked = control.requires_security && (!isExtendedSession || !isSecurityUnlocked);

            return (
              <tr key={control.id} className={securityBlocked ? "security-required" : ""}>
                <td className="control-name">
                  {control.name || control.id}
                </td>
                <td className="security-cell">
                  {control.requires_security ? (
                    <span className="prereq-pills">
                      <span className={`prereq-pill session-extended ${isExtendedSession ? "" : "unmet"}`}>Extended</span>
                      <span className={`prereq-pill security-unlock ${isSecurityUnlocked ? "" : "unmet"}`}>Unlock</span>
                    </span>
                  ) : (
                    <span className="prereq-pill no-security">None</span>
                  )}
                </td>
                <td className="control-state">
                  {control.value != null ? String(control.value) : control.current_state || "-"}
                  {control.frozen && <span className="state-badge frozen-badge">frozen</span>}
                  {control.controlled_by_tester && <span className="state-badge controlled-badge">controlled</span>}
                </td>
                <td className="io-actions-cell">
                  <button
                    className="op-btn io-reset"
                    onClick={() => executeControl(control.id, "reset_to_default")}
                    disabled={isExecutingThis || securityBlocked}
                    title="Reset to default value"
                  >
                    {isExecutingThis ? "..." : "Reset"}
                  </button>
                  <button
                    className="op-btn io-freeze"
                    onClick={() => executeControl(control.id, "freeze_current")}
                    disabled={isExecutingThis || securityBlocked}
                    title="Freeze current value"
                  >
                    {isExecutingThis ? "..." : "Freeze"}
                  </button>
                  <div className="adjust-control">
                    {hasAllowed ? (
                      <select
                        value={currentAdjustValue}
                        onChange={(e) => setAdjustValue(new Map(adjustValue.set(control.id, e.target.value)))}
                        className="adjust-select"
                        disabled={securityBlocked}
                      >
                        <option value="">Select...</option>
                        {control.allowed!.map((opt, i) => (
                          <option key={i} value={String(opt)}>{String(opt)}</option>
                        ))}
                      </select>
                    ) : (
                      <input
                        type="text"
                        placeholder="Value"
                        value={currentAdjustValue}
                        onChange={(e) => setAdjustValue(new Map(adjustValue.set(control.id, e.target.value)))}
                        className="adjust-input"
                        disabled={securityBlocked}
                      />
                    )}
                    <button
                      className="op-btn io-adjust"
                      onClick={() => {
                        let val: unknown = currentAdjustValue;
                        if (!hasAllowed) {
                          if (/^\d+$/.test(currentAdjustValue)) val = parseInt(currentAdjustValue, 10);
                          else if (/^\d+\.\d+$/.test(currentAdjustValue)) val = parseFloat(currentAdjustValue);
                        }
                        executeControl(control.id, "short_term_adjust", val);
                      }}
                      disabled={isExecutingThis || !currentAdjustValue || securityBlocked}
                      title="Short-term adjust"
                    >
                      {isExecutingThis ? "..." : "Adjust"}
                    </button>
                  </div>
                </td>
                <td className={`result-cell ${result?.success === false ? "error" : result?.success ? "success" : ""}`}>
                  {result
                    ? (result.value != null ? String(result.value) : result.new_value || result.message || result.state)
                    : "-"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// =============================================================================
// Software Update Tab
// =============================================================================

interface SoftwareTabProps {
  componentId: string;              // Actual ECU id ("engine_ecu")
  gatewayComponentId?: string | null; // Parent gateway ("uds_gw") or null
  modeTarget?: string | null;       // Path prefix for mode routing ("uds_gw/engine_ecu")
  apiComponentId: string;           // Gateway or self - for parameter reads
  session: SessionMode;
  onUpdateComplete?: () => void;
  allComponentIds: string[];
}

interface ExistingTransfer {
  transfer_id: string;
  state: string;
  error: string | null;
  component_id: string;
}

interface UploadResult {
  upload_id: string;
  file_id: string | null;
  state: string;
}

interface FlashResult {
  transfer_id: string;
  state: string;
  blocks_transferred: number;
  blocks_total: number;
  percent: number | null;
  error: string | null;
}

interface TransferInfo {
  transfer_id: string;
  state: string;
  error: string | null;
}

type FlashPhase = "idle" | "uploading" | "verifying" | "flashing" | "finalizing" | "resetting" | "activated" | "complete" | "committed" | "rolledback" | "error";

interface ActivationInfo {
  supports_rollback: boolean;
  state: string;
  active_version: string | null;
  previous_version: string | null;
}

interface CommitRollbackResult {
  success: boolean;
  message: string | null;
}

// Represents a file selected via browser input or Tauri drag-drop
interface SelectedFileInfo {
  name: string;
  size: number;
  // For browser File API
  file?: File;
  // For Tauri drag-drop (file path)
  path?: string;
}

function SoftwareTab({ componentId, gatewayComponentId, modeTarget, apiComponentId, session, onUpdateComplete, allComponentIds }: SoftwareTabProps) {
  const [phase, setPhase] = useState<FlashPhase>("idle");
  const [progress, setProgress] = useState<number>(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState<SelectedFileInfo | null>(null);
  const [_uploadId, setUploadId] = useState<string | null>(null);
  const [_fileId, setFileId] = useState<string | null>(null);
  const [transferId, setTransferId] = useState<string | null>(null);
  const [existingTransfers, setExistingTransfers] = useState<ExistingTransfer[]>([]);
  const [_checkingTransfers, setCheckingTransfers] = useState(false);
  const completedTransferIds = useRef<Set<string>>(new Set());
  const imperativeFlashRef = useRef(false);
  const [currentSwVersion, setCurrentSwVersion] = useState<string | null>(null);
  const [swVersionBefore, setSwVersionBefore] = useState<string | null>(null);
  const [swVersionAfter, setSwVersionAfter] = useState<string | null>(null);
  const [activationState, setActivationState] = useState<ActivationInfo | null>(null);

  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [...prev, `[${timestamp}] ${message}`]);
  };

  // Mark our transfer as completed so it won't show in existing-transfers warning
  const markTransferCompleted = () => {
    if (transferId) {
      completedTransferIds.current.add(transferId);
    }
  };

  const terminalStates = ["failed", "error", "aborted", "complete", "finished"];

  // Check for existing transfers across ALL ECUs
  const checkExistingTransfers = async () => {
    setCheckingTransfers(true);
    const allActive: ExistingTransfer[] = [];

    for (const compId of allComponentIds) {
      try {
        await invoke("flash_init", { componentId: compId });
        const transfers = await invoke<TransferInfo[]>("flash_list_transfers");
        for (const t of transfers) {
          if (terminalStates.includes(t.state)) continue;
          if (completedTransferIds.current.has(t.transfer_id)) continue;
          allActive.push({ ...t, component_id: compId });
        }
      } catch {
        // Component doesn't support flash — skip
      }
    }

    // Re-init flash client for the current component so future operations work
    try {
      await invoke("flash_init", { componentId: modeTarget || componentId, gatewayId: gatewayComponentId });
    } catch {
      // ignore
    }

    setExistingTransfers(allActive);
    setCheckingTransfers(false);
  };

  // Hydrate flash state from server when tab mounts or ECU changes.
  // Returns true if a non-idle state was restored from the server.
  const hydrateFlashState = async (): Promise<boolean> => {
    try {
      const flashComponentId = modeTarget || componentId;
      await invoke("flash_init", {
        componentId: flashComponentId,
        gatewayId: gatewayComponentId,
      });

      // Check for active/recent transfers on this component
      let transfers: TransferInfo[] = [];
      try {
        transfers = await invoke<TransferInfo[]>("flash_list_transfers");
      } catch {
        return false;
      }

      if (transfers.length > 0) {
        const transfer = transfers[0];
        const state = transfer.state.toLowerCase().replace(/_/g, "");

        // Active transfer states — resume monitoring
        if (["queued", "preparing", "transferring"].includes(state)) {
          setTransferId(transfer.transfer_id);
          setPhase("flashing");
          addLog(`Resumed: active flash transfer (${transfer.state})`);
          return true;
        }

        if (state === "awaitingexit") {
          setTransferId(transfer.transfer_id);
          setPhase("finalizing");
          addLog("Resumed: transfer complete, awaiting finalization");
          return true;
        }

        // Post-finalize states
        if (state === "awaitingreset") {
          setTransferId(transfer.transfer_id);
          setPhase("resetting");
          addLog("Resumed: firmware flashed, awaiting ECU reset");
          return true;
        }

        if (state === "activated") {
          setTransferId(transfer.transfer_id);
          try {
            const activation = await invoke<ActivationInfo>("flash_get_activation");
            setActivationState(activation);
            if (activation.active_version) setSwVersionAfter(activation.active_version);
            if (activation.previous_version) setSwVersionBefore(activation.previous_version);
          } catch { /* ignore */ }
          setPhase("activated");
          addLog("Resumed: firmware activated, awaiting commit or rollback");
          // ECU rebooted — refresh parent session/security display
          onUpdateComplete?.();
          return true;
        }

        if (state === "committed") {
          try {
            const activation = await invoke<ActivationInfo>("flash_get_activation");
            setActivationState(activation);
            if (activation.active_version) setSwVersionAfter(activation.active_version);
            if (activation.previous_version) setSwVersionBefore(activation.previous_version);
          } catch { /* ignore */ }
          setPhase("committed");
          addLog("Firmware was committed successfully");
          onUpdateComplete?.();
          return true;
        }

        if (state === "rolledback") {
          try {
            const activation = await invoke<ActivationInfo>("flash_get_activation");
            setActivationState(activation);
            if (activation.previous_version) setSwVersionBefore(activation.previous_version);
          } catch { /* ignore */ }
          setPhase("rolledback");
          addLog("Firmware was rolled back to previous version");
          onUpdateComplete?.();
          return true;
        }
      }

      // No active transfers — check activation state directly
      // (handles case where transfer record is gone but activation persists)
      try {
        const activation = await invoke<ActivationInfo>("flash_get_activation");
        const state = activation.state.toLowerCase().replace(/_/g, "");

        if (state === "awaitingreset") {
          setPhase("resetting");
          addLog("Resumed: awaiting ECU reset");
          return true;
        }

        if (state === "activated") {
          setActivationState(activation);
          if (activation.active_version) setSwVersionAfter(activation.active_version);
          if (activation.previous_version) setSwVersionBefore(activation.previous_version);
          setPhase("activated");
          addLog("Resumed: firmware activated, awaiting commit or rollback");
          onUpdateComplete?.();
          return true;
        }
      } catch {
        // Activation not supported — stay idle
      }

      return false;
    } catch {
      return false;
    }
  };

  useEffect(() => {
    // Reset state when switching ECUs
    setPhase("idle");
    setProgress(0);
    setError(null);
    setSelectedFile(null);
    setUploadId(null);
    setFileId(null);
    setTransferId(null);
    setSwVersionBefore(null);
    setSwVersionAfter(null);
    setCurrentSwVersion(null);
    setActivationState(null);
    setLogs([]);

    // Hydrate from server state first; only check other transfers if idle
    hydrateFlashState().then((hydrated) => {
      if (!hydrated) {
        checkExistingTransfers();
      }
    });
    // Read current SW version on load
    readSwVersion().then(v => setCurrentSwVersion(v));
  }, [componentId]);

  // Read software version from ECU (parameter reads route through gateway)
  const readSwVersion = async (): Promise<string | null> => {
    try {
      const result = await invoke<DataResponse>("read_parameter", {
        componentId: apiComponentId,
        parameterId: "ecu_sw_version",
        appPath: modeTarget || null,
      });
      return result.value?.toString() || null;
    } catch {
      // DID might not exist
      return null;
    }
  };

  // Re-check transfers when file is selected
  const handleFileSelected = async (fileInfo: SelectedFileInfo) => {
    setSelectedFile(fileInfo);
    addLog(`Selected file: ${fileInfo.name}${fileInfo.size > 0 ? ` (${(fileInfo.size / 1024).toFixed(1)} KB)` : ""}`);
    // Re-check for existing transfers
    await checkExistingTransfers();
  };

  // Listen for Tauri drag-drop events
  useEffect(() => {
    let unlisten: (() => void) | undefined;

    const setupDragDrop = async () => {
      try {
        const webview = getCurrentWebview();
        unlisten = await webview.onDragDropEvent((event) => {
          if (event.payload.type === "over" || event.payload.type === "enter") {
            setIsDragging(true);
          } else if (event.payload.type === "leave") {
            setIsDragging(false);
          } else if (event.payload.type === "drop") {
            setIsDragging(false);
            const paths = event.payload.paths;
            if (paths.length > 0) {
              const filePath = paths[0];
              const fileName = filePath.split(/[/\\]/).pop() || "unknown";
              handleFileSelected({
                name: fileName,
                size: 0,
                path: filePath,
              });
            }
          }
        });
      } catch (e) {
        console.error("Failed to setup drag-drop listener:", e);
      }
    };

    setupDragDrop();

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, []);

  const handleCancelTransfer = async (tid: string, forComponentId: string) => {
    try {
      // Init flash client for the component that owns this transfer
      await invoke("flash_init", { componentId: forComponentId });
      await invoke("flash_abort", { transferId: tid });
      // Also send transfer_exit to clear ECU's download state
      try {
        await invoke("flash_finalize");
      } catch {
        // Ignore - ECU might not be in a state that accepts transfer exit
      }
      addLog(`Cancelled transfer ${tid} on ${forComponentId}`);
      await checkExistingTransfers();
    } catch (e) {
      addLog(`Failed to cancel: ${e}`);
    }
  };

  const resetState = () => {
    setPhase("idle");
    setProgress(0);
    setError(null);
    setSelectedFile(null);
    setUploadId(null);
    setFileId(null);
    setTransferId(null);
    setSwVersionBefore(null);
    setSwVersionAfter(null);
    setActivationState(null);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    // Browser drag-drop (won't fire for filesystem drops in Tauri - those go through onDragDropEvent)
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      handleFileSelected({
        name: file.name,
        size: file.size,
        file: file,
      });
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      const file = files[0];
      handleFileSelected({
        name: file.name,
        size: file.size,
        file: file,
      });
    }
  };

  const startFlashProcess = async () => {
    if (!selectedFile) {
      setError("No file selected");
      return;
    }

    // Note: sovdd bug reports programming session as "extended" - accept both for now
    if (session !== "programming" && session !== "extended") {
      setError("Programming session required for software update");
      return;
    }

    setError(null);
    setLogs([]);
    imperativeFlashRef.current = true;

    try {
      // Initialize flash client (with gateway routing for sub-entities)
      const flashComponentId = modeTarget || componentId;
      addLog(`Initializing flash for ${componentId}${gatewayComponentId ? ` via gateway ${gatewayComponentId}` : ""}...`);
      await invoke("flash_init", { componentId: flashComponentId, gatewayId: gatewayComponentId });

      // Read current SW version before update
      const versionBefore = await readSwVersion();
      if (versionBefore) {
        setSwVersionBefore(versionBefore);
        addLog(`Current SW version: ${versionBefore}`);
      }

      // Phase 1: Upload
      setPhase("uploading");
      setProgress(0);
      addLog(`Uploading ${selectedFile.name}...`);

      let uploadResult: UploadResult;

      if (selectedFile.path) {
        // File from Tauri drag-drop - upload via path
        uploadResult = await invoke<UploadResult>("flash_upload_from_path", {
          path: selectedFile.path,
        });
      } else if (selectedFile.file) {
        // File from browser input - upload via bytes
        const fileData = await selectedFile.file.arrayBuffer();
        const dataArray = Array.from(new Uint8Array(fileData));
        uploadResult = await invoke<UploadResult>("flash_upload", {
          data: dataArray,
          filename: selectedFile.name,
        });
      } else {
        throw new Error("Invalid file selection");
      }

      // Server upload is synchronous - upload_id IS the file_id
      const uploadedFileId = uploadResult.upload_id;
      setUploadId(uploadedFileId);
      setFileId(uploadedFileId);
      setProgress(100);
      addLog(`Upload complete (File ID: ${uploadedFileId})`)

      // Phase 2: Verify
      setPhase("verifying");
      setProgress(0);
      addLog("Verifying package integrity...");

      await invoke("flash_verify", { fileId: uploadedFileId });
      setProgress(100);
      addLog("Verification passed");

      // Ensure programming session before flash (route through gateway for sub-entities)
      addLog("Switching to programming session...");
      await invoke("set_session", { componentId: apiComponentId, session: "programming", target: modeTarget });

      // Phase 3: Flash
      setPhase("flashing");
      setProgress(0);
      addLog("Starting flash transfer to ECU...");

      const flashResult = await invoke<FlashResult>("flash_start", {
        fileId: uploadedFileId,
      });
      setTransferId(flashResult.transfer_id);
      addLog(`Flash started (Transfer ID: ${flashResult.transfer_id})`);

      // Poll flash progress
      let flashComplete = false;
      while (!flashComplete) {
        await new Promise((r) => setTimeout(r, 500));
        const status = await invoke<FlashResult>("flash_poll_progress", {
          transferId: flashResult.transfer_id,
        });

        const percent = status.percent ??
          (status.blocks_total > 0
            ? (status.blocks_transferred / status.blocks_total) * 100
            : 0);
        setProgress(percent);

        if (status.blocks_total > 0) {
          addLog(`Flashing: ${status.blocks_transferred}/${status.blocks_total} blocks (${percent.toFixed(1)}%)`);
        }

        if (status.state === "finished" || status.state === "awaitingexit" || status.state === "completed" || status.state === "complete") {
          flashComplete = true;
          addLog("Flash transfer complete");
        } else if (status.state === "failed" || status.state === "error" || status.state === "aborted") {
          throw new Error(`Flash failed: ${status.error || "Unknown error"}`);
        }
      }

      // Phase 4: Finalize
      setPhase("finalizing");
      setProgress(0);
      addLog("Finalizing transfer...");

      await invoke("flash_finalize");
      addLog("Transfer exit sent");
      setProgress(50);

      // Poll progress to detect awaiting_reset state
      let needsReset = false;
      for (let i = 0; i < 10; i++) {
        await new Promise((r) => setTimeout(r, 500));
        try {
          const status = await invoke<FlashResult>("flash_poll_progress", {
            transferId: flashResult.transfer_id,
          });
          if (status.state === "awaiting_reset" || status.state === "awaitingreset") {
            needsReset = true;
            break;
          }
          if (status.state === "complete" || status.state === "completed" || status.state === "finished") {
            break;
          }
        } catch {
          // Poll may fail if transfer is already done
          break;
        }
      }
      setProgress(100);

      if (needsReset) {
        // ECU needs a reset — stop here and let the user decide
        setPhase("resetting");
        addLog("Awaiting ECU reset. Click 'Reset ECU' or power-cycle the ECU externally.");
      } else {
        // No reset needed — read version and complete
        const versionAfter = await readSwVersion();
        if (versionAfter) {
          setSwVersionAfter(versionAfter);
          addLog(`New SW version: ${versionAfter}`);
        }
        markTransferCompleted();
        setPhase("complete");
        setProgress(100);
        addLog("Software update completed successfully!");
        onUpdateComplete?.();
      }

    } catch (e) {
      setPhase("error");
      setError(String(e));
      addLog(`ERROR: ${e}`);
    } finally {
      imperativeFlashRef.current = false;
    }
  };

  // Finalize a transfer that was hydrated in "awaiting_exit" state
  const handleFinalize = async () => {
    try {
      addLog("Finalizing transfer...");
      await invoke("flash_finalize");
      addLog("Transfer exit sent");

      // Check if ECU needs reset
      if (transferId) {
        await new Promise((r) => setTimeout(r, 500));
        const status = await invoke<FlashResult>("flash_poll_progress", { transferId });
        const state = status.state.toLowerCase().replace(/_/g, "");
        if (state === "awaitingreset") {
          setPhase("resetting");
          addLog("Awaiting ECU reset. Click 'Reset ECU' or power-cycle the ECU externally.");
        } else {
          const versionAfter = await readSwVersion();
          if (versionAfter) {
            setSwVersionAfter(versionAfter);
            addLog(`New SW version: ${versionAfter}`);
          }
          markTransferCompleted();
          setPhase("complete");
          setProgress(100);
          addLog("Software update completed successfully!");
          onUpdateComplete?.();
        }
      }
    } catch (e) {
      setPhase("error");
      setError(String(e));
      addLog(`ERROR: Finalize failed: ${e}`);
    }
  };

  const abortFlash = async () => {
    if (transferId) {
      try {
        addLog("Aborting flash...");
        await invoke("flash_abort", { transferId });
        addLog("Flash aborted");
      } catch (e) {
        addLog(`Abort failed: ${e}`);
      }
    }
    resetState();
  };

  // Send ECU reset command (the background poll will detect when it comes back)
  const handleResetEcu = async () => {
    try {
      addLog("Sending ECU reset...");
      await invoke("flash_reset_ecu");
      addLog("ECU reset command sent — waiting for ECU to reboot and activate firmware...");
    } catch (e) {
      addLog(`ECU reset command failed: ${e}`);
    }
  };

  // Background poll: while in "resetting" phase, keep checking the activation
  // state. The ECU may be rebooting (unreachable) or still in AwaitingReset.
  // Only transition once the ECU reports a state other than AwaitingReset.
  useEffect(() => {
    if (phase !== "resetting") return;

    let active = true;
    let wasOffline = false;
    let pollCount = 0;

    const poll = async () => {
      if (!active) return;
      pollCount++;

      try {
        const activation = await invoke<ActivationInfo>("flash_get_activation");
        if (!active) return;

        if (wasOffline) {
          addLog("ECU is back online.");
          wasOffline = false;
        }

        const state = activation.state.toLowerCase().replace(/_/g, "");
        if (state === "awaitingreset") {
          // Still waiting — keep polling silently
          return;
        }

        // ECU has moved past AwaitingReset — it rebooted, session is now default
        active = false;
        addLog(`Activation state: ${activation.state}`);
        setActivationState(activation);

        // Refresh parent's session/security display (ECU is back in default/locked)
        onUpdateComplete?.();

        if (activation.active_version) {
          setSwVersionAfter(activation.active_version);
          addLog(`Active version: ${activation.active_version}`);
        }
        if (activation.previous_version) {
          addLog(`Previous version: ${activation.previous_version}`);
        }

        if (activation.supports_rollback) {
          setPhase("activated");
          addLog("Firmware activated. Commit to make permanent, or Rollback to revert.");
        } else {
          markTransferCompleted();
          setPhase("complete");
          setProgress(100);
          addLog("Software update completed successfully!");
          onUpdateComplete?.();
        }
      } catch {
        // ECU unreachable (likely rebooting) — keep polling
        if (!wasOffline) {
          wasOffline = true;
          addLog("ECU is offline (rebooting). Polling until it comes back...");
        } else if (pollCount % 10 === 0) {
          addLog(`Still waiting for ECU... (${pollCount * 3}s)`);
        }
      }
    };

    // First poll right away, then every 3 seconds
    poll();
    const intervalId = setInterval(poll, 3000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [phase]); // eslint-disable-line react-hooks/exhaustive-deps

  // Poll flash progress when hydrated into "flashing" phase (not driven by startFlashProcess)
  useEffect(() => {
    if (phase !== "flashing" || !transferId || imperativeFlashRef.current) return;

    let active = true;

    const poll = async () => {
      if (!active) return;

      try {
        const status = await invoke<FlashResult>("flash_poll_progress", { transferId });
        if (!active) return;

        const percent = status.percent ??
          (status.blocks_total > 0 ? (status.blocks_transferred / status.blocks_total) * 100 : 0);
        setProgress(percent);

        const state = status.state.toLowerCase().replace(/_/g, "");

        if (state === "finished" || state === "awaitingexit" || state === "completed" || state === "complete") {
          active = false;
          addLog("Flash transfer complete");
          setPhase("finalizing");
          return;
        }

        if (state === "failed" || state === "error" || state === "aborted") {
          active = false;
          setPhase("error");
          setError(status.error || "Flash transfer failed");
          addLog(`ERROR: ${status.error || "Flash transfer failed"}`);
          return;
        }
      } catch {
        // Transient error — keep polling
      }
    };

    poll();
    const intervalId = setInterval(poll, 1000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [phase, transferId]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleCommit = async () => {
    try {
      addLog("Committing firmware...");
      const result = await invoke<CommitRollbackResult>("flash_commit");
      if (result.success) {
        markTransferCompleted();
        setPhase("committed");
        addLog("Firmware committed successfully — update is permanent.");
        onUpdateComplete?.();
      } else {
        throw new Error(result.message || "Commit failed");
      }
    } catch (e) {
      setPhase("error");
      setError(String(e));
      addLog(`ERROR: Commit failed: ${e}`);
    }
  };

  const handleRollback = async () => {
    try {
      addLog("Rolling back firmware...");
      const result = await invoke<CommitRollbackResult>("flash_rollback");
      if (result.success) {
        markTransferCompleted();
        setPhase("rolledback");
        addLog("Firmware rolled back — reverted to previous version.");
        onUpdateComplete?.();
      } else {
        throw new Error(result.message || "Rollback failed");
      }
    } catch (e) {
      setPhase("error");
      setError(String(e));
      addLog(`ERROR: Rollback failed: ${e}`);
    }
  };

  const phases: { key: FlashPhase; label: string }[] = [
    { key: "uploading", label: "Upload" },
    { key: "verifying", label: "Verify" },
    { key: "flashing", label: "Flash" },
    { key: "finalizing", label: "Finalize" },
    { key: "resetting", label: "Reset" },
    { key: "activated", label: "Activate" },
    { key: "complete", label: "Done" },
  ];

  const getPhaseIndex = (p: FlashPhase): number => {
    // committed and rolledback are terminal states that map to the "Done" step
    if (p === "committed" || p === "rolledback") {
      return phases.findIndex((x) => x.key === "complete");
    }
    const idx = phases.findIndex((x) => x.key === p);
    return idx >= 0 ? idx : -1;
  };

  const currentPhaseIndex = getPhaseIndex(phase);
  const isProcessing = phase !== "idle" && phase !== "complete" && phase !== "error" && phase !== "resetting" && phase !== "activated" && phase !== "committed" && phase !== "rolledback";

  return (
    <div className="software-tab">
      {/* Current Version Display */}
      {currentSwVersion && (
        <div className="current-version">
          <span className="version-label">Current Version:</span>
          <span className="version-value">{currentSwVersion}</span>
        </div>
      )}

      {/* Session Warning */}
      {/* Note: sovdd bug reports programming (0x02) as "extended" - accept both */}
      {session !== "programming" && session !== "extended" && (
        <div className="session-warning">
          Programming session required for software updates. Currently in {session} session.
        </div>
      )}

      {/* Phase Stepper */}
      <div className="phase-stepper">
        {phases.map((p, idx) => (
          <div
            key={p.key}
            className={`phase-step ${
              idx < currentPhaseIndex ? "completed" :
              idx === currentPhaseIndex ? "active" : ""
            } ${phase === "error" && idx === currentPhaseIndex ? "error" : ""}`}
          >
            <div className="phase-number">
              {idx < currentPhaseIndex ? "✓" : idx + 1}
            </div>
            <div className="phase-label">{p.label}</div>
          </div>
        ))}
      </div>

      {/* Progress Bar */}
      {isProcessing && (
        <div className="progress-container">
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <span className="progress-text">{progress.toFixed(0)}%</span>
        </div>
      )}

      {/* Existing Transfers Warning */}
      {phase === "idle" && existingTransfers.length > 0 && (
        <div className="transfers-warning">
          <div className="warning-header">Existing transfers found:</div>
          {existingTransfers.map((t) => (
            <div key={t.transfer_id} className="transfer-item">
              <span className="transfer-component">{t.component_id}</span>
              <span className={`transfer-state state-${t.state}`}>{t.state}</span>
              <span className="transfer-id">{t.transfer_id.slice(0, 8)}...</span>
              {t.error && <span className="transfer-error">{t.error.slice(0, 50)}...</span>}
              <button
                className="cancel-transfer-btn"
                onClick={() => handleCancelTransfer(t.transfer_id, t.component_id)}
              >
                Cancel
              </button>
            </div>
          ))}
          <div className="warning-note">
            Cancel existing transfers before starting a new update.
          </div>
        </div>
      )}

      {/* Drop Zone */}
      {phase === "idle" && (
        <div
          className={`drop-zone ${isDragging ? "dragging" : ""} ${selectedFile ? "has-file" : ""}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {selectedFile ? (
            <div className="selected-file">
              <div className="file-icon">📦</div>
              <div className="file-name">{selectedFile.name}</div>
              <div className="file-size">
                {selectedFile.size > 0 ? `${(selectedFile.size / 1024).toFixed(1)} KB` : "(from drag-drop)"}
              </div>
              <button className="clear-file" onClick={() => setSelectedFile(null)}>×</button>
            </div>
          ) : (
            <>
              <div className="drop-icon">📥</div>
              <div className="drop-text">Drop software package here</div>
              <div className="drop-or">or</div>
              <label className="file-select-btn">
                Browse Files
                <input type="file" onChange={handleFileSelect} style={{ display: "none" }} />
              </label>
            </>
          )}
        </div>
      )}

      {/* Awaiting Reset — shown when ECU needs a reset after flashing */}
      {phase === "resetting" && (
        <div className="awaiting-reset-info">
          <div className="awaiting-reset-header">Awaiting ECU Reset</div>
          <div className="awaiting-reset-hint">
            Firmware has been flashed. Send a reset command or power-cycle the ECU externally.
            Polling for activation state in the background...
          </div>
        </div>
      )}

      {/* Activation Info — shown when firmware is activated but not committed */}
      {phase === "activated" && activationState && (
        <div className="activation-info">
          <div className="activation-header">Firmware Activated — Awaiting Decision</div>
          <div className="activation-versions">
            {activationState.active_version && (
              <div className="activation-version-row">
                <span className="activation-version-label">Active Version</span>
                <span className="activation-version-value active">{activationState.active_version}</span>
              </div>
            )}
            {activationState.previous_version && (
              <div className="activation-version-row">
                <span className="activation-version-label">Previous Version</span>
                <span className="activation-version-value previous">{activationState.previous_version}</span>
              </div>
            )}
          </div>
          <div className="activation-hint">
            Test the new firmware, then commit to make it permanent or rollback to revert.
          </div>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flash-actions">
        {phase === "idle" && (
          <button
            className="flash-btn start"
            onClick={startFlashProcess}
            disabled={!selectedFile || (session !== "programming" && session !== "extended") || existingTransfers.length > 0}
          >
            Start Update
          </button>
        )}

        {isProcessing && (
          <button className="flash-btn abort" onClick={abortFlash}>
            Abort
          </button>
        )}

        {phase === "finalizing" && !imperativeFlashRef.current && (
          <button className="flash-btn start" onClick={handleFinalize}>
            Finalize Transfer
          </button>
        )}

        {phase === "resetting" && (
          <button className="flash-btn start" onClick={handleResetEcu}>
            Reset ECU
          </button>
        )}

        {phase === "activated" && (
          <>
            <button className="flash-btn commit" onClick={handleCommit}>
              Commit
            </button>
            <button className="flash-btn rollback" onClick={handleRollback}>
              Rollback
            </button>
          </>
        )}

        {(phase === "complete" || phase === "error" || phase === "committed" || phase === "rolledback") && (
          <button className="flash-btn reset" onClick={resetState}>
            New Update
          </button>
        )}
      </div>

      {/* Error Display */}
      {error && (
        <div className="flash-error">
          {error}
        </div>
      )}

      {/* Success Display */}
      {phase === "complete" && (
        <div className="flash-success">
          <div>Software update completed successfully!</div>
          {(swVersionBefore || swVersionAfter) && (
            <div className="version-change">
              {swVersionBefore && <span className="version-before">{swVersionBefore}</span>}
              {swVersionBefore && swVersionAfter && <span className="version-arrow"> → </span>}
              {swVersionAfter && <span className="version-after">{swVersionAfter}</span>}
            </div>
          )}
        </div>
      )}

      {/* Committed Display */}
      {phase === "committed" && (
        <div className="flash-success committed">
          <div>Firmware committed — update is permanent.</div>
          {(swVersionBefore || swVersionAfter) && (
            <div className="version-change">
              {swVersionBefore && <span className="version-before">{swVersionBefore}</span>}
              {swVersionBefore && swVersionAfter && <span className="version-arrow"> → </span>}
              {swVersionAfter && <span className="version-after">{swVersionAfter}</span>}
            </div>
          )}
        </div>
      )}

      {/* Rolledback Display */}
      {phase === "rolledback" && (
        <div className="flash-success rolledback">
          <div>Firmware rolled back — reverted to previous version.</div>
          {activationState?.previous_version && (
            <div className="version-change">
              <span className="version-after">{activationState.previous_version}</span>
              <span className="version-label-inline"> (restored)</span>
            </div>
          )}
        </div>
      )}

      {/* Log Output */}
      {logs.length > 0 && (
        <div className="flash-log">
          <div className="log-header">Log Output</div>
          <div className="log-content">
            {logs.map((log, idx) => (
              <div key={idx} className={`log-line ${log.includes("ERROR") ? "error" : ""}`}>
                {log}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
