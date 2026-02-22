# Standard UDS DIDs and Security Level Display

## Standard DID Constants (ISO 14229-1 Annex C)

A shared `standard_did` module was added to `sovd-uds/src/uds/mod.rs` defining
all standard UDS identification DIDs in the 0xF1xx range. This eliminates
duplicated magic hex values across the codebase.

### Constants defined

| Constant | DID | Description |
|----------|------|-------------|
| `BOOT_SOFTWARE_ID` | 0xF180 | Boot Software Identification |
| `APPLICATION_SOFTWARE_ID` | 0xF181 | Application Software Identification |
| `APPLICATION_DATA_ID` | 0xF182 | Application Data Identification |
| `BOOT_SOFTWARE_FINGERPRINT` | 0xF183 | Boot Software Fingerprint |
| `APP_SOFTWARE_FINGERPRINT` | 0xF184 | Application Software Fingerprint |
| `APP_DATA_FINGERPRINT` | 0xF185 | Application Data Fingerprint |
| `ACTIVE_DIAGNOSTIC_SESSION` | 0xF186 | Active Diagnostic Session |
| `SPARE_PART_NUMBER` | 0xF187 | Spare Part Number |
| `ECU_SOFTWARE_NUMBER` | 0xF188 | ECU Software Number |
| `ECU_SOFTWARE_VERSION` | 0xF189 | ECU Software Version Number |
| `SYSTEM_SUPPLIER_ID` | 0xF18A | System Supplier Identifier |
| `ECU_MANUFACTURING_DATE` | 0xF18B | ECU Manufacturing Date |
| `ECU_SERIAL_NUMBER` | 0xF18C | ECU Serial Number |
| `VIN` | 0xF190 | Vehicle Identification Number |
| `ECU_HARDWARE_NUMBER` | 0xF191 | ECU Hardware Number |
| `SUPPLIER_HW_NUMBER` | 0xF192 | System Supplier HW Number |
| `SUPPLIER_HW_VERSION` | 0xF193 | System Supplier HW Version |
| `SUPPLIER_SW_NUMBER` | 0xF194 | System Supplier SW Number |
| `SUPPLIER_SW_VERSION` | 0xF195 | System Supplier SW Version |
| `SYSTEM_NAME` | 0xF197 | System Name or Engine Type |
| `PROGRAMMING_DATE` | 0xF199 | Programming Date |
| `TESTER_SERIAL_NUMBER` | 0xF19E | Tester Serial Number |

The `IDENTIFICATION_DIDS` array provides a canonical list of (did, key, label)
tuples used for enumeration by the test ECU, sovdd server, and explorer.

### Auto-injection

- **Test ECU**: `EcuConfig::ensure_standard_dids()` injects missing standard
  DIDs with sensible defaults so TOML configs only need to define sensor and
  runtime parameters.
- **sovdd server**: `register_standard_dids()` auto-registers standard DIDs as
  `DataType::String` in the DID store so all ECUs decode them without YAML
  entries.

## Writable Parameters

A `writable: bool` field (default `false`) was added through the full stack:
`DidDefinition` -> API response -> client type -> frontend. Only parameters
explicitly marked `writable = true` in config files show the edit button.

Writable by convention (per UDS spec):
- Fingerprint DIDs: 0xF183, 0xF184, 0xF185
- Programming Date: 0xF199
- Tester Serial Number: 0xF19E

## Security Level Display

Security requirements are shown as colored prerequisite pill badges on
operations and I/O controls, matching the header session/security selector
colors:

- **Extended** pill (green): indicates extended or engineering session required
- **Unlock** pill (green/red): indicates security access required

Each pill shows as filled (green) when the prerequisite is met, or outlined and
dimmed when unmet. Action buttons are grayed out when prerequisites aren't met.

For I/O controls, only controls with `security_level > 0` have their buttons
disabled by security state. Controls with `security_level = 0` are freely
usable.

## Software Version DID Convention

Per ISO 14229-1, `0xF189` (ECU Software Version Number) is the canonical
software version identifier. The simulation configs and flash handler use this
DID for the `software_version` parameter. After a flash/reprogram, the test ECU
updates `0xF189` so the header subtitle reflects the new version.

Note: `0xF195` (System Supplier ECU Software Version Number) is the supplier's
internal version and is a separate, supplementary identifier.

## Files Modified

### sovd-uds
- `src/uds/mod.rs` - `standard_did` module with constants and `IDENTIFICATION_DIDS`

### sovd-core
- `src/models/operation.rs` - Added `security_level: u8` to `OperationInfo`
- `src/models/output.rs` - Added `security_level: u8` to `OutputInfo` and `OutputDetail`

### sovd-conv
- `src/definition.rs` - Added `writable: bool` to `DidDefinition`

### sovd-api
- `src/handlers/data.rs` - Added `writable` to `DidInfoResponse`
- `src/handlers/operations.rs` - Added `security_level` to response
- `src/handlers/outputs.rs` - Added `security_level` to response structs

### sovd-client
- `src/types.rs` - Added `writable`, `security_level` to client types

### sovdd
- `src/main.rs` - `register_standard_dids()`, `writable` parsing in inline params

### test-ecu
- `src/config.rs` - `ensure_standard_dids()`, `default_did_value()`, standard DID constants
- `src/parameters.rs` - Flash handler updates `0xF189` instead of `0xF195`

### Simulation configs
- ECU TOML files: `software_version` mapped to `0xF189`
- DID YAML files: `software_version` definition under `0xF189`
- `gateway.toml`: Added writable `programming_date` parameter

### Explorer (SOVDd-explorer)
- `src-tauri/src/lib.rs` - `get_ecu_info` uses `IDENTIFICATION_DIDS`, `IoControlInfo` gains `security_level`
- `src/App.tsx` - Prerequisite pill badges, per-control security gating, writable edit guard, type-aware value encoding
- `src/App.css` - `.prereq-pill` styles matching header color scheme
