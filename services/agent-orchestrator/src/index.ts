/**
 * FHIR R6 Agent Orchestrator - MCP Server
 *
 * Implements Model Context Protocol (JSON-RPC) to expose FHIR tools
 * and context to a Claude-powered agent with explicit guardrails
 * and auditability.
 *
 * Tool tiers:
 * - Read-only (no step-up): context.get, fhir.read, fhir.search
 * - Write (require step-up): fhir.propose_write, fhir.commit_write
 */

import express from "express";
import { v4 as uuidv4 } from "uuid";
import { FHIRTools, ToolTier } from "./tools";

const app = express();
app.use(express.json());

const PORT = process.env.MCP_PORT || 3001;
const FHIR_BASE_URL = process.env.FHIR_BASE_URL || "http://localhost:5000/r6/fhir";

// Initialize FHIR tools
const fhirTools = new FHIRTools(FHIR_BASE_URL);

// --- MCP Discovery Endpoint ---

interface MCPToolSchema {
  name: string;
  description: string;
  tier: ToolTier;
  inputSchema: Record<string, unknown>;
}

app.get("/mcp/tools", (_req, res) => {
  const tools: MCPToolSchema[] = fhirTools.getToolSchemas();
  res.json({
    jsonrpc: "2.0",
    result: {
      tools,
      serverInfo: {
        name: "fhir-r6-agent-orchestrator",
        version: "0.1.0",
        protocolVersion: "2024-11-05",
      },
    },
  });
});

// --- MCP JSON-RPC Endpoint ---

interface JSONRPCRequest {
  jsonrpc: string;
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

app.post("/mcp/rpc", async (req, res) => {
  const rpcRequest: JSONRPCRequest = req.body;

  if (!rpcRequest || rpcRequest.jsonrpc !== "2.0") {
    return res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32600, message: "Invalid JSON-RPC request" },
      id: null,
    });
  }

  const { id, method, params } = rpcRequest;

  try {
    switch (method) {
      case "tools/list": {
        const tools = fhirTools.getToolSchemas();
        return res.json({ jsonrpc: "2.0", id, result: { tools } });
      }

      case "tools/call": {
        const toolName = params?.name as string;
        const toolInput = params?.arguments as Record<string, unknown>;
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
          toolInput || {},
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
    const message = error instanceof Error ? error.message : "Internal error";
    return res.json({
      jsonrpc: "2.0",
      id,
      error: { code: -32603, message },
    });
  }
});

// --- Health Check ---

app.get("/health", (_req, res) => {
  res.json({
    status: "healthy",
    service: "fhir-r6-agent-orchestrator",
    fhirBaseUrl: FHIR_BASE_URL,
    timestamp: new Date().toISOString(),
  });
});

// --- Start Server ---

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`MCP Agent Orchestrator running on port ${PORT}`);
    console.log(`FHIR Base URL: ${FHIR_BASE_URL}`);
  });
}

export { app };
