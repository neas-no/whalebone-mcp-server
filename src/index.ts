#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

// Configuration interface
interface WhaleboneConfig {
  accessKey: string;
  secretKey: string;
  baseUrl?: string;
  maxResults?: number;
  maxResponseSize?: number;
  enableTruncation?: boolean;
}

// Response constraints
const DEFAULT_MAX_RESULTS = 50;
const DEFAULT_MAX_RESPONSE_SIZE = 50000; // ~50KB of JSON
const MAX_STRING_LENGTH = 1000; // Max length for individual string fields

// Server configuration - you can adjust these limits via environment variables
const config: WhaleboneConfig = {
  accessKey: process.env.WHALEBONE_ACCESS_KEY || "",
  secretKey: process.env.WHALEBONE_SECRET_KEY || "",
  baseUrl: process.env.WHALEBONE_BASE_URL || "https://api.whalebone.io/whalebone/2",
  maxResults: parseInt(process.env.WHALEBONE_MAX_RESULTS || DEFAULT_MAX_RESULTS.toString()),
  maxResponseSize: parseInt(process.env.WHALEBONE_MAX_RESPONSE_SIZE || DEFAULT_MAX_RESPONSE_SIZE.toString()),
  enableTruncation: process.env.WHALEBONE_ENABLE_TRUNCATION !== "false", // Default to true
};

class WhaleboneClient {
  private config: WhaleboneConfig;

  constructor(config: WhaleboneConfig) {
    this.config = config;
  }

  private truncateString(str: string, maxLength: number = MAX_STRING_LENGTH): string {
    if (!this.config.enableTruncation || str.length <= maxLength) {
      return str;
    }
    return str.substring(0, maxLength) + "... [truncated]";
  }

  private truncateObject(obj: any): any {
    if (!this.config.enableTruncation) {
      return obj;
    }

    if (typeof obj === 'string') {
      return this.truncateString(obj);
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.truncateObject(item));
    }
    
    if (obj && typeof obj === 'object') {
      const truncated: any = {};
      for (const [key, value] of Object.entries(obj)) {
        truncated[key] = this.truncateObject(value);
      }
      return truncated;
    }
    
    return obj;
  }

  private limitResults(data: any, maxResults: number = this.config.maxResults || DEFAULT_MAX_RESULTS): any {
    if (Array.isArray(data)) {
      const limited = data.slice(0, maxResults);
      if (data.length > maxResults) {
        return {
          results: limited,
          total_available: data.length,
          returned: limited.length,
          truncated: true,
          message: `Results limited to ${maxResults} items out of ${data.length} total. Use pagination parameters to access more results.`
        };
      }
      return limited;
    }
    
    // Handle objects that contain arrays (like timeline buckets)
    if (data && typeof data === 'object') {
      const result: any = {};
      for (const [key, value] of Object.entries(data)) {
        if (Array.isArray(value)) {
          result[key] = this.limitResults(value, maxResults);
        } else {
          result[key] = value;
        }
      }
      return result;
    }
    
    return data;
  }

  private enforceResponseSize(data: any): any {
    const jsonString = JSON.stringify(data);
    const maxSize = this.config.maxResponseSize || DEFAULT_MAX_RESPONSE_SIZE;
    
    if (jsonString.length <= maxSize) {
      return data;
    }

    // If response is too large, progressively reduce it
    if (Array.isArray(data)) {
      const itemSize = Math.floor(jsonString.length / data.length);
      const maxItems = Math.floor(maxSize / itemSize * 0.8); // 80% safety margin
      
      return {
        results: data.slice(0, Math.max(1, maxItems)),
        total_available: data.length,
        returned: Math.max(1, maxItems),
        truncated: true,
        message: `Response truncated due to size constraints. Showing ${Math.max(1, maxItems)} of ${data.length} items.`
      };
    }

    // For objects, truncate string fields more aggressively
    return this.truncateObject(data);
  }

  private processResponse(data: any): any {
    // First limit the number of results
    let processed = this.limitResults(data);
    
    // Then truncate long strings
    processed = this.truncateObject(processed);
    
    // Finally ensure total response size is manageable
    processed = this.enforceResponseSize(processed);
    
    return processed;
  }

  private async makeRequest(endpoint: string, params: Record<string, any> = {}) {
    const url = new URL(`${this.config.baseUrl}${endpoint}`);
    
    // Add query parameters
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        if (Array.isArray(value)) {
          value.forEach(v => url.searchParams.append(key, v.toString()));
        } else {
          url.searchParams.append(key, value.toString());
        }
      }
    });

    const headers = {
      'Wb-Access-Key': this.config.accessKey,
      'Wb-Secret-Key': this.config.secretKey,
      'Content-Type': 'application/json',
    };

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers,
    });

    if (!response.ok) {
      throw new Error(`Whalebone API error: ${response.status} ${response.statusText}`);
    }

    const rawData = await response.json();
    return this.processResponse(rawData);
  }

  async searchEvents(params: any) {
    return this.makeRequest('/events/search', params);
  }

  async getEventsTimeline(params: any) {
    return this.makeRequest('/events/timeline', params);
  }

  async getEventsStats(params: any) {
    return this.makeRequest('/events/stats', params);
  }

  async getDnsTimeline(params: any) {
    return this.makeRequest('/dns/timeline', params);
  }

  async getDnssecTimeline(params: any) {
    return this.makeRequest('/dnssec/timeline', params);
  }

  async getIocCount() {
    return this.makeRequest('/ioc/count');
  }

  async getResolverMetrics(params: any) {
    return this.makeRequest('/resolver/metrics', params);
  }

  async getDomainAnalysis(fqdn: string) {
    return this.makeRequest('/domain/analysis', { fqdn });
  }

  // Privacy-sensitive endpoints - commented out by default
  // Uncomment these methods if you need access to audit logs or identity protection data
  // async getAuditLogs(params: any) {
  //   return this.makeRequest('/audit/logs', params);
  // }

  // async getIdpIncidents(params: any) {
  //   return this.makeRequest('/idp/incidents', params);
  // }
}

// Define available tools
const tools: Tool[] = [
  {
    name: "search_events",
    description: "Search for security events detected by Whalebone. Results are automatically limited to prevent context overflow.",
    inputSchema: {
      type: "object",
      properties: {
        client_ip: { type: "string", description: "Source IP address (supports * wildcard)" },
        threat_type: { 
          type: "string", 
          enum: ["c&c", "blacklist", "malware", "phishing", "spam", "coinminer", "compromised"],
          description: "Type of threat to filter by" 
        },
        resolver_id: { type: "integer", description: "ID of the resolver" },
        domain: { type: "string", description: "Domain name (supports * wildcard)" },
        device_id: { type: "array", items: { type: "string" }, description: "Device identifiers" },
        subscription_id: { type: "string", description: "Subscription identifier" },
        action: { type: "string", enum: ["log", "block", "allow"], description: "Event action" },
        days: { type: "integer", minimum: 1, maximum: 220, default: 1, description: "Number of days to look back (default: 1)" },
        hours: { type: "integer", minimum: 1, maximum: 5280, description: "Number of hours to look back" },
        scroll: { type: "boolean", default: false, description: "Enable scrolling for large result sets (not recommended for context efficiency)" },
        sort: { type: "string", enum: ["asc", "desc"], default: "desc", description: "Sort order (newest first by default)" }
      }
    }
  },
  {
    name: "get_events_timeline",
    description: "Get timeline of security events",
    inputSchema: {
      type: "object",
      properties: {
        client_ip: { type: "string", description: "Source IP address (supports * wildcard)" },
        threat_type: { 
          type: "string", 
          enum: ["c&c", "blacklist", "malware", "phishing", "spam", "coinminer", "compromised"],
          description: "Type of threat to filter by" 
        },
        resolver_id: { type: "integer", description: "ID of the resolver" },
        domain: { type: "string", description: "Domain name (supports * wildcard)" },
        device_id: { type: "array", items: { type: "string" }, description: "Device identifiers" },
        subscription_id: { type: "string", description: "Subscription identifier" },
        action: { type: "string", enum: ["log", "block", "allow"], description: "Event action" },
        days: { type: "integer", minimum: 1, maximum: 220, description: "Number of days to look back" },
        hours: { type: "integer", minimum: 1, maximum: 5280, description: "Number of hours to look back" },
        aggregate: { 
          type: "string", 
          enum: ["client_ip", "action", "threat_type", "resolver_id", "domain", "device_id", "subscription_id", "country"],
          description: "Aggregate timeline buckets by parameter" 
        },
        interval: { type: "string", enum: ["hour", "day", "week", "month"], description: "Timeline bucket size" }
      }
    }
  },
  {
    name: "get_events_stats",
    description: "Get aggregated statistics for security events",
    inputSchema: {
      type: "object",
      properties: {
        client_ip: { type: "string", description: "Source IP address (supports * wildcard)" },
        threat_type: { 
          type: "string", 
          enum: ["c&c", "blacklist", "malware", "phishing", "spam", "coinminer", "compromised"],
          description: "Type of threat to filter by" 
        },
        resolver_id: { type: "integer", description: "ID of the resolver" },
        domain: { type: "string", description: "Domain name (supports * wildcard)" },
        device_id: { type: "array", items: { type: "string" }, description: "Device identifiers" },
        subscription_id: { type: "string", description: "Subscription identifier" },
        action: { type: "string", enum: ["log", "block", "allow"], description: "Event action" },
        days: { type: "integer", minimum: 1, maximum: 220, description: "Number of days to look back" },
        hours: { type: "integer", minimum: 1, maximum: 5280, description: "Number of hours to look back" },
        aggregate: { 
          type: "string", 
          enum: ["client_ip", "action", "threat_type", "resolver_id", "domain", "device_id", "subscription_id", "country"],
          description: "Aggregate statistics by parameter" 
        }
      }
    }
  },
  {
    name: "get_dns_timeline",
    description: "Get DNS traffic timeline. Results are automatically limited and aggregated for context efficiency.",
    inputSchema: {
      type: "object",
      properties: {
        client_ip: { type: "string", description: "Source IP address (supports * wildcard)" },
        query_type: { 
          type: "string", 
          enum: ["a", "aaaa", "afsdb", "apl", "caa", "cdnskey", "cds", "cert", "cname", "dhcid", "dlv", "dname", "dnskey", "ds", "hip", "ipseckey", "key", "kx", "loc", "mx", "naptr", "ns", "nsec", "nsec3", "nsec3param", "openpgpkey", "ptr", "rrsig", "rp", "sig", "soa", "srv", "sshfp", "ta", "tkey", "tlsa", "tsig", "txt", "uri", "aname"],
          description: "Type of DNS query" 
        },
        domain: { type: "string", description: "Second level domain name (supports * wildcard)" },
        query: { type: "string", description: "Complete query string (supports * wildcard)" },
        days: { type: "integer", minimum: 1, maximum: 14, default: 1, description: "Number of days to look back (default: 1)" },
        hours: { type: "integer", minimum: 1, maximum: 336, description: "Number of hours to look back" },
        resolver_id: { type: "integer", description: "ID of the resolver" },
        device_id: { type: "array", items: { type: "string" }, description: "Device identifiers" },
        answer: { type: "string", description: "Filter by answer content (supports * wildcard)" },
        dga: { type: "boolean", description: "Filter only DGA domains" },
        tld: { type: "string", description: "Filter by TLD (supports * wildcard)" },
        aggregate: { 
          type: "string", 
          enum: ["client_ip", "tld", "domain", "query", "answer", "query_type", "device_id", "country"],
          default: "query_type",
          description: "Aggregate timeline buckets by parameter (default: query_type for efficiency)" 
        },
        interval: { type: "string", enum: ["hour", "day", "week", "month"], default: "hour", description: "Timeline bucket size (default: hour)" }
      }
    }
  },
  {
    name: "get_dnssec_timeline",
    description: "Get DNSSEC traffic timeline",
    inputSchema: {
      type: "object",
      properties: {
        query_type: { 
          type: "string", 
          enum: ["a", "aaaa", "afsdb", "apl", "caa", "cdnskey", "cds", "cert", "cname", "dhcid", "dlv", "dname", "dnskey", "ds", "hip", "ipseckey", "key", "kx", "loc", "mx", "naptr", "ns", "nsec", "nsec3", "nsec3param", "openpgpkey", "ptr", "rrsig", "rp", "sig", "soa", "srv", "sshfp", "ta", "tkey", "tlsa", "tsig", "txt", "uri", "aname"],
          description: "Type of DNS query" 
        },
        domain: { type: "string", description: "Second level domain name (supports * wildcard)" },
        query: { type: "string", description: "Complete query string (supports * wildcard)" },
        days: { type: "integer", minimum: 1, maximum: 14, description: "Number of days to look back" },
        hours: { type: "integer", minimum: 1, maximum: 336, description: "Number of hours to look back" },
        resolver_id: { type: "integer", description: "ID of the resolver" },
        tld: { type: "string", description: "Filter by TLD (supports * wildcard)" },
        aggregate: { 
          type: "string", 
          enum: ["tld", "domain", "query", "query_type"],
          description: "Aggregate timeline buckets by parameter" 
        },
        interval: { type: "string", enum: ["hour", "day", "week", "month"], description: "Timeline bucket size" }
      }
    }
  },
  {
    name: "get_ioc_count",
    description: "Get counts of active Indicators of Compromise (IOCs) per threat type",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "get_resolver_metrics",
    description: "Get timeline metrics of client resolvers",
    inputSchema: {
      type: "object",
      properties: {
        resolver_id: { type: "integer", description: "ID of the resolver" },
        days: { type: "integer", minimum: 1, maximum: 220, description: "Number of days to look back" },
        hours: { type: "integer", minimum: 1, maximum: 5280, description: "Number of hours to look back" },
        interval: { type: "string", enum: ["hour", "day", "week", "month"], description: "Timeline interval size" }
      }
    }
  },
  {
    name: "analyze_domain",
    description: "Get domain analysis including threats and content categories",
    inputSchema: {
      type: "object",
      properties: {
        fqdn: { type: "string", description: "Fully Qualified Domain Name (max 253 characters)" }
      },
      required: ["fqdn"]
    }
  },
  // {
  //   name: "get_audit_logs",
  //   description: "Get audit logs",
  //   inputSchema: {
  //     type: "object",
  //     properties: {
  //       resolver_id: { type: "integer", description: "ID of the resolver" },
  //       days: { type: "integer", minimum: 1, maximum: 220, description: "Number of days to look back" },
  //       hours: { type: "integer", minimum: 1, maximum: 5280, description: "Number of hours to look back" },
  //       event: { type: "string", description: "Filter by event type (supports * wildcard)" },
  //       category: { type: "string", description: "Filter by category (supports * wildcard)" },
  //       result: { type: "string", enum: ["success", "failure"], description: "Filter by result" },
  //       rw: { type: "string", enum: ["read", "write"], description: "Filter by action type" },
  //       sort: { type: "string", enum: ["asc", "desc"], description: "Sort order" },
  //       user: { type: "string", description: "Filter by user" }
  //     }
  //   }
  // },
  // {
  //   name: "get_idp_incidents",
  //   description: "List Identity Protection incidents grouped by assets",
  //   inputSchema: {
  //     type: "object",
  //     properties: {
  //       subscription_id: { type: "string", description: "Subscription identifier (required for email/phone asset types)" },
  //       asset_type: { type: "string", enum: ["email", "phone", "domain"], description: "Type of asset to filter incidents" },
  //       asset_value: { type: "string", description: "Specific asset value to filter by" },
  //       language: { type: "string", description: "Language code for breach description (default: en)" },
  //       limit: { type: "integer", minimum: 1, maximum: 500, description: "Number of rows to return (default: 50)" },
  //       scroll_token: { type: "string", description: "Token for pagination" }
  //     }
  //   }
  // }
];

// Create the server
const server = new Server({
  name: "whalebone-mcp-server",
  version: "1.0.0",
}, {
  capabilities: {
    tools: {},
  },
});

// Initialize Whalebone client
const whalebone = new WhaleboneClient(config);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result;
    const toolArgs = args || {};
    
    switch (name) {
      case "search_events":
        result = await whalebone.searchEvents(toolArgs);
        break;
      case "get_events_timeline":
        result = await whalebone.getEventsTimeline(toolArgs);
        break;
      case "get_events_stats":
        result = await whalebone.getEventsStats(toolArgs);
        break;
      case "get_dns_timeline":
        result = await whalebone.getDnsTimeline(toolArgs);
        break;
      case "get_dnssec_timeline":
        result = await whalebone.getDnssecTimeline(toolArgs);
        break;
      case "get_ioc_count":
        result = await whalebone.getIocCount();
        break;
      case "get_resolver_metrics":
        result = await whalebone.getResolverMetrics(toolArgs);
        break;
      case "analyze_domain":
        if (!toolArgs.fqdn) {
          throw new Error("fqdn parameter is required");
        }
        result = await whalebone.getDomainAnalysis(toolArgs.fqdn as string);
        break;
      // Privacy-sensitive endpoints are commented out by default
      // Uncomment these in your local deployment if you need access to audit logs or identity data
      // case "get_audit_logs":
      //   result = await whalebone.getAuditLogs(toolArgs);
      //   break;
      // case "get_idp_incidents":
      //   result = await whalebone.getIdpIncidents(toolArgs);
      //   break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    
    // Provide helpful context about size limits if relevant
    let helpfulError = errorMessage;
    if (errorMessage.includes('too large') || errorMessage.includes('truncated')) {
      helpfulError += `\n\nTip: Try using more specific filters (date ranges, domains, IPs) or pagination to get smaller result sets.`;
    }
    
    return {
      content: [
        {
          type: "text",
          text: `Error: ${helpfulError}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Whalebone MCP server running on stdio");
}

main().catch(console.error);