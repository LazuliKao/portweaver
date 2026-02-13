/**
 * TypeScript definitions matching the Zig configuration types
 * Source: src/config/types.zig, src/config/json_loader.zig
 *
 * This file is used to generate JSON Schema for PortWeaver configuration validation.
 * Keep this in sync with Zig code when making changes.
 */

/**
 * Address family restriction
 */
export type AddressFamily = "any" | "ipv4" | "ipv6";

/**
 * Protocol type
 */
export type Protocol = "both" | "tcp" | "udp";

/**
 * DDNS IP get method
 */
export type DdnsIpGetType = "url" | "net_interface" | "cmd";

/**
 * FRP client node configuration
 */
export interface FrpcNode {
  /** Whether this node is enabled */
  enabled?: boolean;
  /** FRP server address */
  server: string;
  /** FRP server port */
  port: number;
  /** Authentication token */
  token?: string;
  /** Log level */
  log_level?: string;
  /** Use encryption */
  use_encryption?: boolean;
  /** Use compression */
  use_compression?: boolean;
}

/**
 * FRP server node configuration
 */
export interface FrpsNode {
  /** Whether this node is enabled */
  enabled?: boolean;
  /** Server listening port */
  port: number;
  /** Authentication token */
  token?: string;
  /** Log level */
  log_level?: string;
  /** Allowed ports (e.g., "8000-9000,10000") */
  allow_ports?: string;
  /** Bind address */
  bind_addr?: string;
  /** Maximum pool count */
  max_pool_count?: number;
  /** Maximum ports per client */
  max_ports_per_client?: number;
  /** Enable TCP multiplexing */
  tcp_mux?: boolean;
  /** Enable UDP multiplexing */
  udp_mux?: boolean;
  /** Enable KCP multiplexing */
  kcp_mux?: boolean;
  /** Dashboard address */
  dashboard_addr?: string;
  /** Dashboard username */
  dashboard_user?: string;
  /** Dashboard password */
  dashboard_pwd?: string;
}

/**
 * FRP forwarding configuration
 * In JSON: can be string "node_name:port" or object {node_name, remote_port}
 */
export interface FrpcForward {
  /** Node name */
  node_name: string;
  /** Remote port */
  remote_port: number;
}

/**
 * Port mapping: one listen port range to one target port range
 */
export interface PortMapping {
  /** Listen port (supports range like "8080-8090" or single port like "8080" or number) */
  listen_port: number | string;
  /** Target port (supports range like "80-90" or single port like "80" or number) */
  target_port: number | string;
  /** Protocol: TCP+UDP / TCP / UDP */
  protocol?: Protocol;
  /** FRP forwarding list (can be string "node:port" or object) */
  frpc?: (string | FrpcForward)[];
}

/**
 * DDNS configuration
 * IPv4/IPv6 config fields are flattened with prefixes in JSON
 */
export interface DdnsConfig {
  /** Whether this config is enabled */
  enabled?: boolean;
  /** Configuration name (for display and identification) */
  name: string;
  /** DNS provider */
  dns_provider: string;
  /** DNS ID (required by some providers) */
  dns_id?: string;
  /** DNS Secret/Token */
  dns_secret?: string;
  /** DNS extended parameter (e.g., Vercel Team ID) */
  dns_ext_param?: string;
  /** TTL in seconds */
  ttl?: number;

  // IPv4 config (flattened with ipv4_ prefix)
  ipv4_enable?: boolean;
  ipv4_get_type?: DdnsIpGetType;
  ipv4_url?: string;
  ipv4_net_interface?: string;
  ipv4_cmd?: string;
  ipv4_domains?: string;

  // IPv6 config (flattened with ipv6_ prefix)
  ipv6_enable?: boolean;
  ipv6_get_type?: DdnsIpGetType;
  ipv6_url?: string;
  ipv6_net_interface?: string;
  ipv6_cmd?: string;
  ipv6_reg?: string;
  ipv6_domains?: string;

  /** Disable WAN access */
  not_allow_wan_access?: boolean;
  /** Username (required by some providers) */
  username?: string;
  /** Password (required by some providers) */
  password?: string;
  /** Webhook URL */
  webhook_url?: string;
  /** Webhook request body */
  webhook_body?: string;
  /** Webhook request headers */
  webhook_headers?: string;
}

/**
 * Port forwarding project/rule
 *
 * Two modes (mutually exclusive):
 * 1. Single-port mode: listen_port + target_port
 * 2. Multi-port mode: port_mappings array
 */
export interface Project {
  /** Whether this project is enabled */
  enabled?: boolean;
  /** Description/remark */
  remark?: string;
  /** Source firewall zone(s) - string or array of strings */
  src_zone?: string | string[];
  /** Destination firewall zone(s) - string or array of strings */
  dest_zone?: string | string[];
  /** Address family restriction */
  family?: AddressFamily;
  /** Protocol (only valid in single-port mode) */
  protocol?: Protocol;
  /** Listen port (single-port mode) */
  listen_port?: number;
  /** Target address (required) */
  target_address: string;
  /** Target port (single-port mode) */
  target_port?: number;
  /** Port mappings (multi-port mode, mutually exclusive with listen_port/target_port) */
  port_mappings?: PortMapping[];
  /** Open firewall port */
  open_firewall_port?: boolean;
  /** Add firewall forward rule */
  add_firewall_forward?: boolean;
  /** Preserve source IP (only when add_firewall_forward=true) */
  preserve_source_ip?: boolean;
  /** Enable application-layer forwarding (Zig network lib, like socat) */
  enable_app_forward?: boolean;
  /** Reuse address when binding */
  reuseaddr?: boolean;
  /** Enable traffic statistics (only when enable_app_forward=true) */
  enable_stats?: boolean;
}

/**
 * Full configuration object format
 * JSON can also be just Project[] array (shorthand)
 */
export interface PortWeaverConfigObject {
  /** Port forwarding projects */
  projects: Project[];
  /** FRP client nodes (key is node name) */
  frpc_nodes?: Record<string, FrpcNode>;
  /** FRP server nodes (key is node name) */
  frps_nodes?: Record<string, FrpsNode>;
  /** DDNS configurations */
  ddns?: DdnsConfig[];
}

/**
 * PortWeaver configuration
 * Supports two formats:
 * 1. Object: { projects: [...], frpc_nodes: {...}, ... }
 * 2. Array: Project[] (shorthand, only projects)
 */
export type PortWeaverConfig = (PortWeaverConfigObject | Project[]) & {
  $schema?: string;
};
