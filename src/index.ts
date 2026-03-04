import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { GetEnvKeysSchema, getEnvKeys } from "./tools/get-env-keys.js";
import { RunWithEnvSchema, runWithEnv } from "./tools/run-with-env.js";
import { ApiCallSchema, apiCall } from "./tools/api-call.js";
import { SyncExampleSchema, syncExample } from "./tools/sync-example.js";

const server = new McpServer({
  name: "secure-api",
  version: "1.0.0",
});

server.tool(
  "get_env_keys",
  "Returns the list of environment variable key names from a project's .env file. No values are exposed.",
  GetEnvKeysSchema.shape,
  async (args) => {
    const result = await getEnvKeys(args);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

server.tool(
  "run_with_env",
  "Runs a shell command with .env variables injected into the process environment. Output is sanitized — secret values are replaced with opaque [REDACTED:N] placeholders.",
  RunWithEnvSchema.shape,
  async (args) => {
    const result = await runWithEnv(args);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

server.tool(
  "api_call",
  "Makes an HTTP request with secrets from .env injected into headers. Use auth_env_key for Bearer tokens, or {{KEY_NAME}} syntax in headers for other auth patterns. Response is sanitized.",
  ApiCallSchema.shape,
  async (args) => {
    const result = await apiCall(args);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

server.tool(
  "sync_env_example",
  "Generates or updates .env.example from a project's .env file. Preserves structure and comments, strips values, uses smart placeholders. Merges with existing .env.example.",
  SyncExampleSchema.shape,
  async (args) => {
    const result = await syncExample(args);
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
