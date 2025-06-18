# Whalebone MCP Server

A Model Context Protocol (MCP) server that provides access to the Whalebone cybersecurity API.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your Whalebone API credentials
(not neededed if specified in claude config)
```

3. Build the project:
```bash
npm run build
```

## Configuration

Add this to your Claude Desktop configuration file:

### Windows
`%APPDATA%\Claude\claude_desktop_config.json`

### macOS
`~/Library/Application Support/Claude/claude_desktop_config.json`

### Linux
`~/.config/claude/claude_desktop_config.json`

Configuration (you may have to specify full path to node if its not in path):
```json
{
  "mcpServers": {
    "whalebone": {
      "command": "node",
      "args": ["/path/to/whalebone-mcp-server/dist/index.js"],
      "env": {
        "WHALEBONE_ACCESS_KEY": "your_access_key",
        "WHALEBONE_SECRET_KEY": "your_secret_key",
        "WHALEBONE_BASE_URL": "https://api.eu-01.whalebone.io./whalebone/2"
      }
    }
  }
}
```

## Available Tools

- `search_events` - Search for security events
- `get_events_timeline` - Get timeline of security events
- `get_events_stats` - Get aggregated event statistics
- `get_dns_timeline` - Get DNS traffic timeline
- `get_dnssec_timeline` - Get DNSSEC traffic timeline
- `get_ioc_count` - Get IOC counts by threat type
- `get_resolver_metrics` - Get resolver performance metrics
- `analyze_domain` - Analyze domain for threats and categories
- `get_audit_logs` - Get audit logs
- `get_idp_incidents` - Get identity protection incidents

## Usage Examples

Once configured, you can ask Claude things like:

- "Search for malware events in the last 24 hours"
- "Analyze the domain example.com for threats"
- "Show me DNS timeline for queries to *.google.com"
- "Get resolver metrics for resolver ID 42"
- "What are the current IOC counts by threat type?"

## API Documentation

This MCP server implements the Whalebone API v2. For detailed parameter documentation, refer to the Whalebone API documentation.
