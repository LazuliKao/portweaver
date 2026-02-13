# PortWeaver JSON Schema Generator

TypeScript definitions for generating JSON Schema for PortWeaver configuration files.

## Usage

```bash
pnpm install
pnpm run generate
```

Or use the shell scripts:
```bash
./generate-schema.sh   # Linux/macOS
generate-schema.bat    # Windows
```

## Generated File

- `../docs/portweaver-config.schema.json` - Complete configuration schema

Supports two config formats:
1. Object: `{ "projects": [...], "frpc_nodes": {...}, ... }`
2. Array: `[{ "target_address": "...", ... }]` (shorthand)

## Usage in Config Files

```json
{
  "$schema": "./docs/portweaver-config.schema.json",
  "projects": [
    {
      "target_address": "192.168.1.100",
      "listen_port": 80,
      "target_port": 8080
    }
  ]
}
```

## Type Definitions

`schema-types.ts` mirrors the Zig types from `src/config/types.zig` and JSON parsing from `src/config/json_loader.zig`.

### Key JSON Differences

1. **DDNS fields**: Flattened with prefixes (`ipv4_enable`, `ipv6_url`, etc.)
2. **Zones**: `src_zone`/`dest_zone` accept string or array
3. **Port mappings**: `listen_port`/`target_port` accept number or string (for ranges)
4. **FRP forwarding**: Can be string `"node:port"` or object `{node_name, remote_port}`

## Keeping in Sync

When modifying Zig types:
1. Update `schema-types.ts` to match `json_loader.zig`
2. Run `pnpm run generate`
3. Commit both TypeScript and generated schema
