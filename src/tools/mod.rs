use rmcp::{
    ErrorData,
    handler::server::{ServerHandler, tool::ToolRouter, wrapper::Parameters},
    model::*,
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct TracepointInfo {
    pub name: String,
    pub category: String,
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct KernelFunctionInfo {
    pub name: String,
    pub address: Option<String>,
    pub module: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BtfTypeInfo {
    pub name: String,
    pub kind: String,
    pub size: Option<u32>,
    pub members: Option<Vec<String>>,
}

// Parameter structs for MCP tools
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListTracepointsParams {
    #[schemars(description = "Filter by category name (substring match)")]
    pub category: Option<String>,
    #[schemars(description = "Filter by tracepoint name or category (substring match)")]
    pub pattern: Option<String>,
    #[schemars(description = "Maximum number of results to return (default: 100)")]
    pub limit: Option<usize>,
    #[schemars(description = "Number of results to skip for pagination")]
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListKernelFunctionsParams {
    #[schemars(description = "Filter by function name (substring match)")]
    pub pattern: Option<String>,
    #[schemars(description = "Maximum number of results to return (default: 100)")]
    pub limit: Option<usize>,
    #[schemars(description = "Number of results to skip for pagination")]
    pub offset: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListBpfProgramTypesParams {
    #[schemars(description = "Filter by type name or description (substring match)")]
    pub pattern: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ListBpfMapTypesParams {
    #[schemars(description = "Filter by map type name or description (substring match)")]
    pub pattern: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GetBtfTypesParams {
    #[schemars(description = "Filter by type name (substring match)")]
    pub pattern: Option<String>,
    #[schemars(description = "Maximum number of results to return (default: 100)")]
    pub limit: Option<usize>,
    #[schemars(description = "Number of results to skip for pagination")]
    pub offset: Option<usize>,
}

#[derive(Clone)]
pub struct BpfToolHandler {
    tool_router: ToolRouter<Self>,
}

impl Default for BpfToolHandler {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for tracepoint processing
const TRACEPOINTS_PATH: &str = "/sys/kernel/debug/tracing/events";

/// Reads the format file for a tracepoint event
fn read_event_format(event_path: &Path) -> Option<String> {
    let format_path = event_path.join("format");
    format_path
        .exists()
        .then(|| fs::read_to_string(format_path).ok())
        .flatten()
}

/// Checks if a filename should be skipped (not a real tracepoint event)
fn should_skip_event(name: &str) -> bool {
    matches!(name, "enable" | "filter")
}

/// Processes a single tracepoint category directory
fn process_category(category_entry: fs::DirEntry) -> Vec<TracepointInfo> {
    let category_name = category_entry.file_name().to_string_lossy().to_string();
    let category_path = category_entry.path();

    if !category_path.is_dir() {
        return Vec::new();
    }

    let Ok(event_entries) = fs::read_dir(&category_path) else {
        return Vec::new();
    };

    event_entries
        .flatten()
        .filter_map(|event_entry| {
            let event_name = event_entry.file_name().to_string_lossy().to_string();

            if should_skip_event(&event_name) {
                return None;
            }

            Some(TracepointInfo {
                name: format!("{}:{}", category_name, event_name),
                category: category_name.clone(),
                format: read_event_format(&event_entry.path()),
            })
        })
        .collect()
}

#[tool_router]
impl BpfToolHandler {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Lists all available kernel tracepoints from debugfs.
    ///
    /// This tool reads tracepoint information from `/sys/kernel/debug/tracing/events`
    /// and returns details about each available tracepoint including its name, category,
    /// and format specification.
    ///
    /// # Parameters
    /// - `category`: Optional filter by category name (substring match)
    /// - `pattern`: Optional filter by tracepoint name or category (substring match)
    /// - `limit`: Maximum number of results to return (default: 100)
    /// - `offset`: Number of results to skip for pagination (default: 0)
    ///
    /// # Returns
    /// JSON array of `TracepointInfo` objects containing:
    /// - `name`: Full tracepoint name (e.g., "sched:sched_switch")
    /// - `category`: Tracepoint category (e.g., "sched")
    /// - `format`: Optional format specification from the tracepoint's format file
    ///
    /// # Requirements
    /// - Debugfs must be mounted at `/sys/kernel/debug`
    /// - Read access to tracepoint directories
    #[tool(
        description = "List available kernel tracepoints with optional filtering and pagination"
    )]
    async fn list_tracepoints(
        &self,
        params: Parameters<ListTracepointsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let pattern = params.0.pattern.clone();
        let limit = params.0.limit;
        // Verify tracepoints directory exists
        if !Path::new(TRACEPOINTS_PATH).exists() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Tracepoints directory not accessible. Make sure debugfs is mounted and you have permissions.",
            )]));
        }

        // Read and process all tracepoint categories
        let entries = fs::read_dir(TRACEPOINTS_PATH).map_err(|e| {
            CallToolResult::error(vec![Content::text(format!(
                "Failed to read tracepoints directory: {}",
                e
            ))])
        });

        let Ok(entries) = entries else {
            return Ok(CallToolResult::error(vec![Content::text(
                "Failed to read tracepoints directory",
            )]));
        };

        // Process each category and collect all tracepoints
        let mut tracepoints: Vec<TracepointInfo> =
            entries.flatten().flat_map(process_category).collect();

        // Apply pattern filter (matches both category and name)
        if let Some(ref filter) = pattern {
            tracepoints.retain(|tp| tp.name.contains(filter) || tp.category.contains(filter));
        }

        // Sort by name for consistent output
        tracepoints.sort_by(|a, b| a.name.cmp(&b.name));

        // Apply offset and limit for pagination
        let offset = params.0.offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let tracepoints: Vec<TracepointInfo> =
            tracepoints.into_iter().skip(offset).take(limit).collect();

        // Serialize to JSON
        serde_json::to_string(&tracepoints)
            .map(|json_str| CallToolResult::success(vec![Content::text(json_str)]))
            .map_err(|e| {
                CallToolResult::error(vec![Content::text(format!(
                    "Failed to serialize tracepoints: {}",
                    e
                ))])
            })
            .or_else(Ok)
    }

    /// Lists kernel functions available for attaching kprobes and kretprobes.
    ///
    /// This tool reads the kernel symbol table from `/proc/kallsyms` and returns
    /// information about kernel functions that can be used as attachment points
    /// for BPF kprobe and kretprobe programs.
    ///
    /// # Parameters
    /// - `pattern`: Optional filter by function name (substring match)
    /// - `limit`: Maximum number of results to return (default: 100)
    /// - `offset`: Number of results to skip for pagination (default: 0)
    ///
    /// # Returns
    /// JSON array of `KernelFunctionInfo` objects containing:
    /// - `name`: Function name (e.g., "do_sys_open")
    /// - `address`: Kernel address of the function (if available)
    /// - `module`: Optional module name if the function is from a kernel module
    ///
    /// # Requirements
    /// - Read access to `/proc/kallsyms`
    /// - Symbol types 't', 'T', 'w', 'W' are included (text/weak symbols)
    #[tool(
        description = "List kernel functions available for kprobes/kretprobes with optional filtering and pagination"
    )]
    async fn list_kernel_functions(
        &self,
        params: Parameters<ListKernelFunctionsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let pattern = params.0.pattern.clone();
        let limit = params.0.limit;
        let kallsyms_path = "/proc/kallsyms";
        let mut functions = Vec::new();

        if !Path::new(kallsyms_path).exists() {
            return Ok(CallToolResult::error(vec![Content::text(
                "Cannot access /proc/kallsyms. Make sure you have proper permissions.",
            )]));
        }

        let content = match fs::read_to_string(kallsyms_path) {
            Ok(content) => content,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to read /proc/kallsyms: {}",
                    e
                ))]));
            }
        };

        // Collect all matching functions
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let address = parts[0];
                let symbol_type = parts[1];
                let name = parts[2];
                let module = if parts.len() > 3 {
                    Some(parts[3].trim_matches(['[', ']']).to_string())
                } else {
                    None
                };

                if matches!(symbol_type, "t" | "T" | "w" | "W") {
                    // Apply pattern filter
                    if let Some(ref filter) = pattern
                        && !name.contains(filter)
                    {
                        continue;
                    }

                    functions.push(KernelFunctionInfo {
                        name: name.to_string(),
                        address: Some(address.to_string()),
                        module,
                    });
                }
            }
        }

        // Apply offset and limit for pagination
        let offset = params.0.offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let functions: Vec<KernelFunctionInfo> =
            functions.into_iter().skip(offset).take(limit).collect();

        match serde_json::to_string(&functions) {
            Ok(json_str) => Ok(CallToolResult::success(vec![Content::text(json_str)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize functions: {}",
                e
            ))])),
        }
    }

    /// Retrieves BTF (BPF Type Format) type information from the kernel.
    ///
    /// This tool reads BTF data from `/sys/kernel/btf/vmlinux` and provides
    /// detailed type information about kernel data structures, making it easier
    /// to write BPF programs that interact with kernel structures.
    ///
    /// # Parameters
    /// - `pattern`: Optional filter by type name (substring match)
    /// - `limit`: Maximum number of results to return (default: 100)
    /// - `offset`: Number of results to skip for pagination (default: 0)
    ///
    /// # Returns
    /// JSON array of `BtfTypeInfo` objects containing:
    /// - `name`: Type name (e.g., "task_struct", "file")
    /// - `kind`: Type kind (e.g., "Struct", "Union", "Enum", "Typedef")
    /// - `size`: Size in bytes (if applicable)
    /// - `members`: Array of member names for structs/unions (if applicable)
    ///
    /// # Requirements
    /// - Kernel with BTF support (CONFIG_DEBUG_INFO_BTF=y)
    /// - Access to `/sys/kernel/btf/vmlinux`
    ///
    /// # Example
    /// Querying for "struct file" will return its size (184 bytes) and all member fields
    /// like f_lock, f_mode, f_op, f_mapping, etc.
    #[tool(
        description = "Get BTF type information from the kernel with optional filtering and pagination"
    )]
    async fn get_btf_types(
        &self,
        params: Parameters<GetBtfTypesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let pattern = params.0.pattern.clone();
        let limit = params.0.limit;
        let offset = params.0.offset;
        let btf_path = "/sys/kernel/btf/vmlinux";
        let mut types = Vec::new();

        if !Path::new(btf_path).exists() {
            return Ok(CallToolResult::error(vec![Content::text(
                "BTF information not available. Make sure your kernel supports BTF.",
            )]));
        }

        // Use btf-rs library
        let btf = match btf_rs::Btf::from_file(btf_path) {
            Ok(btf) => btf,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to load BTF data: {}",
                    e
                ))]));
            }
        };

        // Iterate through type IDs (starting from 1, 0 is void)
        // Collect all matching types first for proper offset/limit pagination
        for type_id in 1..=100000_u32 {
            // Try to resolve type by ID
            let btf_type = match btf.resolve_type_by_id(type_id) {
                Ok(t) => t,
                Err(_) => break, // No more types
            };

            // Extract type information based on the type variant
            let (type_name, kind, size, members) = match &btf_type {
                btf_rs::Type::Void => continue, // Skip void types
                btf_rs::Type::Int(int_type) => {
                    let name = btf.resolve_name(int_type).unwrap_or_default();
                    (name, "Int".to_string(), Some(int_type.size() as u32), None)
                }
                btf_rs::Type::Ptr(_) => ("(pointer)".to_string(), "Ptr".to_string(), None, None),
                btf_rs::Type::Array(arr) => {
                    let name = btf.resolve_name(arr).unwrap_or_default();
                    (name, "Array".to_string(), None, None)
                }
                btf_rs::Type::Struct(struct_type) => {
                    let name = btf.resolve_name(struct_type).unwrap_or_default();
                    let member_names: Vec<String> = struct_type
                        .members
                        .iter()
                        .map(|m| btf.resolve_name(m).unwrap_or("(unnamed)".to_string()))
                        .collect();
                    (
                        name,
                        "Struct".to_string(),
                        Some(struct_type.size() as u32),
                        Some(member_names),
                    )
                }
                btf_rs::Type::Union(union_type) => {
                    let name = btf.resolve_name(union_type).unwrap_or_default();
                    let member_names: Vec<String> = union_type
                        .members
                        .iter()
                        .map(|m| btf.resolve_name(m).unwrap_or("(unnamed)".to_string()))
                        .collect();
                    (
                        name,
                        "Union".to_string(),
                        Some(union_type.size() as u32),
                        Some(member_names),
                    )
                }
                btf_rs::Type::Enum(enum_type) => {
                    let name = btf.resolve_name(enum_type).unwrap_or_default();
                    (name, "Enum".to_string(), None, None)
                }
                btf_rs::Type::Fwd(_) => ("(forward)".to_string(), "Fwd".to_string(), None, None),
                btf_rs::Type::Typedef(typedef) => {
                    let name = btf.resolve_name(typedef).unwrap_or_default();
                    (name, "Typedef".to_string(), None, None)
                }
                btf_rs::Type::Volatile(_) => {
                    ("(volatile)".to_string(), "Volatile".to_string(), None, None)
                }
                btf_rs::Type::Const(_) => ("(const)".to_string(), "Const".to_string(), None, None),
                btf_rs::Type::Restrict(_) => {
                    ("(restrict)".to_string(), "Restrict".to_string(), None, None)
                }
                btf_rs::Type::Func(func) => {
                    let name = btf.resolve_name(func).unwrap_or_default();
                    (name, "Func".to_string(), None, None)
                }
                btf_rs::Type::FuncProto(_) => (
                    "(funcproto)".to_string(),
                    "FuncProto".to_string(),
                    None,
                    None,
                ),
                btf_rs::Type::Var(var) => {
                    let name = btf.resolve_name(var).unwrap_or_default();
                    (name, "Var".to_string(), None, None)
                }
                btf_rs::Type::Datasec(datasec) => {
                    let name = btf.resolve_name(datasec).unwrap_or_default();
                    (name, "Datasec".to_string(), None, None)
                }
                btf_rs::Type::Float(float) => {
                    let name = btf.resolve_name(float).unwrap_or_default();
                    (name, "Float".to_string(), Some(float.size() as u32), None)
                }
                btf_rs::Type::DeclTag(_) => {
                    ("(decltag)".to_string(), "DeclTag".to_string(), None, None)
                }
                btf_rs::Type::TypeTag(_) => {
                    ("(typetag)".to_string(), "TypeTag".to_string(), None, None)
                }
                btf_rs::Type::Enum64(enum64) => {
                    let name = btf.resolve_name(enum64).unwrap_or_default();
                    (name, "Enum64".to_string(), None, None)
                }
            };

            // Skip unnamed types
            if type_name.is_empty() || type_name.starts_with('(') {
                continue;
            }

            // Apply pattern filter
            if let Some(ref filter) = pattern
                && !type_name.contains(filter)
            {
                continue;
            }

            types.push(BtfTypeInfo {
                name: type_name,
                kind,
                size,
                members,
            });
        }

        // Apply offset and limit for pagination
        let offset = offset.unwrap_or(0);
        let limit = limit.unwrap_or(100);
        let types: Vec<BtfTypeInfo> = types.into_iter().skip(offset).take(limit).collect();

        match serde_json::to_string(&types) {
            Ok(json_str) => Ok(CallToolResult::success(vec![Content::text(json_str)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize BTF types: {}",
                e
            ))])),
        }
    }

    /// Lists all supported BPF program types with descriptions.
    ///
    /// This tool provides a comprehensive reference of available BPF program types,
    /// helping developers understand which program type to use for different
    /// use cases (tracing, networking, security, etc.).
    ///
    /// # Returns
    /// JSON object mapping program type names to their descriptions. Examples include:
    /// - `kprobe`: Kernel function entry probe
    /// - `tracepoint`: Kernel tracepoint probe
    /// - `xdp`: eXpress Data Path network packet processing
    /// - `cgroup_skb`: Control group socket buffer
    /// - `perf_event`: Performance monitoring events
    ///
    /// # Notes
    /// This is a static reference list and does not query the kernel directly.
    /// Actual kernel support may vary depending on kernel version and configuration.
    #[tool(description = "List supported BPF program types and their descriptions")]
    async fn list_bpf_program_types(&self) -> Result<CallToolResult, ErrorData> {
        let mut program_types = HashMap::new();

        program_types.insert(
            "socket_filter".to_string(),
            "Socket packet filtering".to_string(),
        );
        program_types.insert(
            "kprobe".to_string(),
            "Kernel function entry probe".to_string(),
        );
        program_types.insert(
            "kretprobe".to_string(),
            "Kernel function return probe".to_string(),
        );
        program_types.insert(
            "tracepoint".to_string(),
            "Kernel tracepoint probe".to_string(),
        );
        program_types.insert(
            "xdp".to_string(),
            "eXpress Data Path network packet processing".to_string(),
        );
        program_types.insert(
            "perf_event".to_string(),
            "Performance monitoring events".to_string(),
        );
        program_types.insert(
            "cgroup_skb".to_string(),
            "Control group socket buffer".to_string(),
        );
        program_types.insert(
            "cgroup_sock".to_string(),
            "Control group socket operations".to_string(),
        );
        program_types.insert(
            "lwt_in".to_string(),
            "Lightweight tunnel ingress".to_string(),
        );
        program_types.insert(
            "lwt_out".to_string(),
            "Lightweight tunnel egress".to_string(),
        );
        program_types.insert(
            "lwt_xmit".to_string(),
            "Lightweight tunnel transmit".to_string(),
        );
        program_types.insert("sock_ops".to_string(), "Socket operations".to_string());
        program_types.insert("sk_skb".to_string(), "Socket SKB programs".to_string());
        program_types.insert(
            "cgroup_device".to_string(),
            "Control group device access".to_string(),
        );
        program_types.insert("sk_msg".to_string(), "Socket message programs".to_string());
        program_types.insert(
            "raw_tracepoint".to_string(),
            "Raw kernel tracepoints".to_string(),
        );
        program_types.insert(
            "cgroup_sock_addr".to_string(),
            "Control group socket address".to_string(),
        );
        program_types.insert(
            "lwt_seg6local".to_string(),
            "Segment routing v6 local".to_string(),
        );
        program_types.insert(
            "lirc_mode2".to_string(),
            "Linux Infrared Remote Control".to_string(),
        );
        program_types.insert(
            "sk_reuseport".to_string(),
            "Socket reuseport programs".to_string(),
        );
        program_types.insert(
            "flow_dissector".to_string(),
            "Network flow dissection".to_string(),
        );

        match serde_json::to_string(&program_types) {
            Ok(json_str) => Ok(CallToolResult::success(vec![Content::text(json_str)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize program types: {}",
                e
            ))])),
        }
    }

    /// Lists all supported BPF map types with descriptions.
    ///
    /// This tool provides a comprehensive reference of available BPF map types,
    /// which are data structures used by BPF programs to store and share data
    /// between BPF programs and userspace.
    ///
    /// # Returns
    /// JSON object mapping map type names to their descriptions. Examples include:
    /// - `hash`: Hash table for key-value storage
    /// - `array`: Array indexed by integers
    /// - `ringbuf`: Ring buffer for efficient data transfer
    /// - `perf_event_array`: Array for perf event communication
    /// - `lru_hash`: LRU hash table with automatic eviction
    ///
    /// # Notes
    /// This is a static reference list and does not query the kernel directly.
    /// Actual kernel support may vary depending on kernel version and configuration.
    #[tool(description = "List supported BPF map types and their descriptions")]
    async fn list_bpf_map_types(&self) -> Result<CallToolResult, ErrorData> {
        let mut map_types = HashMap::new();

        map_types.insert(
            "hash".to_string(),
            "Hash table for key-value storage".to_string(),
        );
        map_types.insert("array".to_string(), "Array indexed by integers".to_string());
        map_types.insert(
            "prog_array".to_string(),
            "Array of BPF programs for tail calls".to_string(),
        );
        map_types.insert(
            "perf_event_array".to_string(),
            "Array for perf event communication".to_string(),
        );
        map_types.insert("percpu_hash".to_string(), "Per-CPU hash table".to_string());
        map_types.insert("percpu_array".to_string(), "Per-CPU array".to_string());
        map_types.insert("stack_trace".to_string(), "Stack trace storage".to_string());
        map_types.insert(
            "cgroup_array".to_string(),
            "Array of cgroup file descriptors".to_string(),
        );
        map_types.insert("lru_hash".to_string(), "LRU hash table".to_string());
        map_types.insert(
            "lru_percpu_hash".to_string(),
            "Per-CPU LRU hash table".to_string(),
        );
        map_types.insert(
            "lpm_trie".to_string(),
            "Longest prefix match trie".to_string(),
        );
        map_types.insert(
            "array_of_maps".to_string(),
            "Array containing other maps".to_string(),
        );
        map_types.insert(
            "hash_of_maps".to_string(),
            "Hash table containing other maps".to_string(),
        );
        map_types.insert(
            "devmap".to_string(),
            "Device map for XDP redirect".to_string(),
        );
        map_types.insert(
            "sockmap".to_string(),
            "Socket map for socket redirection".to_string(),
        );
        map_types.insert(
            "cpumap".to_string(),
            "CPU map for XDP CPU redirect".to_string(),
        );
        map_types.insert("xskmap".to_string(), "AF_XDP socket map".to_string());
        map_types.insert("sockhash".to_string(), "Socket hash map".to_string());
        map_types.insert(
            "cgroup_storage".to_string(),
            "Per-cgroup storage".to_string(),
        );
        map_types.insert(
            "reuseport_sockarray".to_string(),
            "Reuseport socket array".to_string(),
        );
        map_types.insert(
            "percpu_cgroup_storage".to_string(),
            "Per-CPU cgroup storage".to_string(),
        );
        map_types.insert("queue".to_string(), "FIFO queue".to_string());
        map_types.insert("stack".to_string(), "LIFO stack".to_string());
        map_types.insert("sk_storage".to_string(), "Socket-local storage".to_string());
        map_types.insert("devmap_hash".to_string(), "Device hash map".to_string());
        map_types.insert(
            "struct_ops".to_string(),
            "Kernel struct operations".to_string(),
        );
        map_types.insert(
            "ringbuf".to_string(),
            "Ring buffer for efficient data transfer".to_string(),
        );

        match serde_json::to_string(&map_types) {
            Ok(json_str) => Ok(CallToolResult::success(vec![Content::text(json_str)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to serialize map types: {}",
                e
            ))])),
        }
    }
}

#[tool_handler]
impl ServerHandler for BpfToolHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "MCP server for inspecting Linux kernel BPF capabilities".to_string(),
            ),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_should_skip_event() {
        assert!(should_skip_event("enable"));
        assert!(should_skip_event("filter"));
        assert!(!should_skip_event("sched_switch"));
        assert!(!should_skip_event("irq_handler_entry"));
    }

    #[test]
    fn test_read_event_format_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let result = read_event_format(&temp_dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn test_read_event_format_exists() {
        let temp_dir = TempDir::new().unwrap();
        let format_path = temp_dir.path().join("format");
        let mut file = fs::File::create(&format_path).unwrap();
        writeln!(file, "name: test_event").unwrap();
        writeln!(file, "ID: 123").unwrap();

        let result = read_event_format(&temp_dir.path());
        assert!(result.is_some());
        let content = result.unwrap();
        assert!(content.contains("name: test_event"));
        assert!(content.contains("ID: 123"));
    }

    #[test]
    fn test_process_category_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let category_dir = temp_dir.path().join("test_category");
        fs::create_dir(&category_dir).unwrap();

        let entry = fs::read_dir(temp_dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let tracepoints = process_category(entry);

        assert_eq!(tracepoints.len(), 0);
    }

    #[test]
    fn test_process_category_with_events() {
        let temp_dir = TempDir::new().unwrap();
        let category_dir = temp_dir.path().join("sched");
        fs::create_dir(&category_dir).unwrap();

        // Create a valid event
        let event_dir = category_dir.join("sched_switch");
        fs::create_dir(&event_dir).unwrap();
        let mut format_file = fs::File::create(event_dir.join("format")).unwrap();
        writeln!(format_file, "name: sched_switch").unwrap();

        // Create files that should be skipped
        fs::File::create(category_dir.join("enable")).unwrap();
        fs::File::create(category_dir.join("filter")).unwrap();

        let entry = fs::read_dir(temp_dir.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let tracepoints = process_category(entry);

        assert_eq!(tracepoints.len(), 1);
        assert_eq!(tracepoints[0].name, "sched:sched_switch");
        assert_eq!(tracepoints[0].category, "sched");
        assert!(tracepoints[0].format.is_some());
        assert!(
            tracepoints[0]
                .format
                .as_ref()
                .unwrap()
                .contains("sched_switch")
        );
    }

    #[tokio::test]
    async fn test_list_tracepoints_no_directory() {
        let handler = BpfToolHandler::new();
        let params = Parameters(ListTracepointsParams {
            category: None,
            pattern: None,
            limit: None,
            offset: None,
        });
        let result = handler.list_tracepoints(params).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());

        // Check if the path exists - if it does, should be success; if not, should be error
        if Path::new(TRACEPOINTS_PATH).exists() {
            assert_ne!(
                call_result.is_error,
                Some(true),
                "Should succeed when tracepoints path exists"
            );
        } else {
            assert_eq!(
                call_result.is_error,
                Some(true),
                "Should return error when tracepoints path doesn't exist"
            );
        }
    }

    #[tokio::test]
    async fn test_list_kernel_functions() {
        let handler = BpfToolHandler::new();
        let params = Parameters(ListKernelFunctionsParams {
            pattern: None,
            limit: None,
            offset: None,
        });
        let result = handler.list_kernel_functions(params).await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());

        // Check if /proc/kallsyms exists - if it does, should succeed
        if Path::new("/proc/kallsyms").exists() {
            assert_ne!(
                call_result.is_error,
                Some(true),
                "Should succeed when /proc/kallsyms exists"
            );
        } else {
            assert_eq!(
                call_result.is_error,
                Some(true),
                "Should return error when /proc/kallsyms doesn't exist"
            );
        }
    }

    #[tokio::test]
    async fn test_list_bpf_program_types() {
        let handler = BpfToolHandler::new();
        let result = handler.list_bpf_program_types().await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());

        // Static list should NEVER return an error
        assert_ne!(
            call_result.is_error,
            Some(true),
            "Static list should never fail"
        );
    }

    #[tokio::test]
    async fn test_list_bpf_map_types() {
        let handler = BpfToolHandler::new();
        let result = handler.list_bpf_map_types().await;
        assert!(result.is_ok());

        let call_result = result.unwrap();
        assert!(!call_result.content.is_empty());

        // Static list should NEVER return an error
        assert_ne!(
            call_result.is_error,
            Some(true),
            "Static list should never fail"
        );
    }
}
