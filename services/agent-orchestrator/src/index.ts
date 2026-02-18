/**
 * FHIR R6 Agent Orchestrator - MCP Server
 *
 * Uses the official @modelcontextprotocol/sdk to expose FHIR tools
 * via the Model Context Protocol with SSE transport.
 *
 * Transports:
 * - SSE: GET /sse + POST /messages (standard MCP transport)
 * - HTTP bridge: POST /mcp/rpc (convenience for non-MCP clients)
 *
 * Tool tiers:
 * - Read-only (no step-up): context.get, fhir.read, fhir.search
 * - Write (require step-up): fhir.propose_write, fhir.commit_write
 */

import express from "express";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { FHIRTools } from "./tools";

const app = express();
app.use(express.json());

const PORT = process.env.MCP_PORT || 3001;
const FHIR_BASE_URL =
  process.env.FHIR_BASE_URL || "http://localhost:5000/r6/fhir";

// Initialize FHIR tools
const fhirTools = new FHIRTools(FHIR_BASE_URL);

// --- MCP Server (using official SDK) ---

const mcpServer = new Server(
  { name: "fhir-r6-agent-orchestrator", version: "0.2.0" },
  { capabilities: { tools: {} } }
);

// Register tool list handler
mcpServer.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools: fhirTools.getMCPToolSchemas() };
});

// Register tool call handler
mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const toolArgs = (args ?? {}) as Record<string, unknown>;

  // Extract step-up token from internal param if present
  const stepUpToken = toolArgs._stepUpToken as string | undefined;
  delete toolArgs._stepUpToken;

  const result = await fhirTools.executeTool(
    name,
    toolArgs,
    stepUpToken
  );

  return {
    content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
  };
});

// --- SSE Transport (standard MCP) ---

const activeSessions = new Map<string, SSEServerTransport>();

app.get("/sse", async (req, res) => {
  const transport = new SSEServerTransport("/messages", res);
  activeSessions.set(transport.sessionId, transport);

  res.on("close", () => {
    activeSessions.delete(transport.sessionId);
  });

  await mcpServer.connect(transport);
});

app.post("/messages", async (req, res) => {
  const sessionId = req.query.sessionId as string;
  const transport = activeSessions.get(sessionId);
  if (!transport) {
    return res.status(400).json({ error: "Invalid or expired session" });
  }
  await transport.handlePostMessage(req, res);
});

// --- Legacy HTTP Bridge (for Python agent_client) ---

interface JSONRPCRequest {
  jsonrpc: string;
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

app.post("/mcp/rpc", async (req, res) => {
  const rpcRequest: JSONRPCRequest = req.body;

  if (!rpcRequest || rpcRequest.jsonrpc !== "2.0" || !rpcRequest.method) {
    return res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid JSON-RPC request" },
      id: rpcRequest?.id ?? null,
    });
  }

  const { id, method, params } = rpcRequest;

  try {
    switch (method) {
      case "tools/list": {
        const tools = fhirTools.getMCPToolSchemas();
        return res.json({ jsonrpc: "2.0", id, result: { tools } });
      }

      case "tools/call": {
        const toolName = params?.name as string;
        const toolInput = (params?.arguments ?? {}) as Record<string, unknown>;
        const stepUpToken = params?.stepUpToken as string | undefined;

        if (!toolName) {
          return res.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32602, message: "Missing tool name" },
          });
        }

        const result = await fhirTools.executeTool(
          toolName,
          toolInput,
          stepUpToken
        );
        return res.json({ jsonrpc: "2.0", id, result });
      }

      case "context/get": {
        const contextId = params?.contextId as string;
        if (!contextId) {
          return res.json({
            jsonrpc: "2.0",
            id,
            error: { code: -32602, message: "Missing contextId" },
          });
        }
        const context = await fhirTools.getContext(contextId);
        return res.json({ jsonrpc: "2.0", id, result: context });
      }

      default:
        return res.json({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `Method not found: ${method}` },
        });
    }
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : "Unknown error";
    console.error(`RPC error for method ${method}:`, detail);
    return res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32603, message: "Internal error" },
    });
  }
});

// --- Health Check ---

app.get("/health", (_req, res) => {
  res.json({
    status: "healthy",
    service: "fhir-r6-agent-orchestrator",
    protocol: "MCP/SSE",
    protocolVersion: "2024-11-05",
    fhirBaseUrl: FHIR_BASE_URL,
    timestamp: new Date().toISOString(),
  });
});

// --- Start Server ---

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`MCP Agent Orchestrator (SSE transport) running on port ${PORT}`);
    console.log(`FHIR Base URL: ${FHIR_BASE_URL}`);
    console.log(`SSE endpoint: http://localhost:${PORT}/sse`);
    console.log(`HTTP bridge: http://localhost:${PORT}/mcp/rpc`);
  });
}

export { app, mcpServer };
