/**
 * FHIR R6 Tool Definitions and Executor.
 *
 * Two tiers:
 * - Read-only (no step-up): context.get, fhir.read, fhir.search, fhir.validate
 * - Write (require step-up): fhir.propose_write, fhir.commit_write
 *
 * All tools include MCP annotations (readOnlyHint, destructiveHint, openWorldHint)
 * required by both Anthropic Connectors Directory and OpenAI MCP Apps.
 */

import fetch from "node-fetch";

export type ToolTier = "read" | "write";

interface ToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
}

interface ToolDefinition {
  name: string;
  description: string;
  tier: ToolTier;
  annotations: ToolAnnotations;
  inputSchema: Record<string, unknown>;
}

// MCP SDK tool schema format (includes annotations)
export interface MCPToolSchema {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: ToolAnnotations;
}

// Cap search results for token safety (marketplace limit: <25k tokens)
const MAX_RESULT_ENTRIES = 50;

export class FHIRTools {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  /**
   * Return tool schemas in MCP SDK format (for ListToolsRequestSchema handler).
   * Includes annotations required by OpenAI and Anthropic marketplaces.
   */
  getMCPToolSchemas(): MCPToolSchema[] {
    return this.getToolSchemas().map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
      annotations: t.annotations,
    }));
  }

  getToolSchemas(): ToolDefinition[] {
    return [
      {
        name: "context.get",
        description:
          "Retrieve a pre-built context envelope with patient-centric FHIR resources. Returns bounded, policy-stamped, time-limited context.",
        tier: "read",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            context_id: { type: "string", description: "Context envelope ID" },
          },
          required: ["context_id"],
        },
      },
      {
        name: "fhir.read",
        description: "Read a specific FHIR R6 resource by type and ID. Returns redacted resource with PHI protection.",
        tier: "read",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            resource_type: {
              type: "string",
              enum: [
                "Patient",
                "Encounter",
                "Observation",
                "AuditEvent",
                "Consent",
              ],
            },
            resource_id: { type: "string", description: "The resource ID" },
          },
          required: ["resource_type", "resource_id"],
        },
      },
      {
        name: "fhir.search",
        description:
          "Search for FHIR R6 resources with basic filtering. Returns paginated, redacted results.",
        tier: "read",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            resource_type: {
              type: "string",
              enum: [
                "Patient",
                "Encounter",
                "Observation",
                "AuditEvent",
                "Consent",
              ],
            },
            patient: {
              type: "string",
              description: "Patient reference filter",
            },
            _count: {
              type: "integer",
              description: "Max results (1-50, capped for token safety)",
              default: 20,
            },
          },
          required: ["resource_type"],
        },
      },
      {
        name: "fhir.validate",
        description:
          "Validate a proposed FHIR R6 resource against structural rules. Returns OperationOutcome.",
        tier: "read",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            resource: {
              type: "object",
              description: "The FHIR resource to validate",
            },
          },
          required: ["resource"],
        },
      },
      {
        name: "fhir.propose_write",
        description:
          "Propose a write — validates the resource and returns a preview. Does NOT commit. Safe to call without step-up authorization.",
        tier: "write",
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            resource: {
              type: "object",
              description: "The FHIR resource to write",
            },
            operation: {
              type: "string",
              enum: ["create", "update"],
              description: "Write operation type",
            },
          },
          required: ["resource", "operation"],
        },
      },
      {
        name: "fhir.commit_write",
        description:
          "Commit a previously proposed write. Requires step-up authorization token. This is a destructive operation.",
        tier: "write",
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
        inputSchema: {
          type: "object",
          properties: {
            resource: {
              type: "object",
              description: "The FHIR resource to commit",
            },
            operation: {
              type: "string",
              enum: ["create", "update"],
            },
          },
          required: ["resource", "operation"],
        },
      },
    ];
  }

  async executeTool(
    toolName: string,
    input: Record<string, unknown>,
    headers?: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const tool = this.getToolSchemas().find((t) => t.name === toolName);
    if (!tool) {
      return { error: `Unknown tool: ${toolName}` };
    }

    // Enforce step-up for commit_write
    if (tool.tier === "write" && toolName === "fhir.commit_write") {
      const stepUpToken = headers?.["x-step-up-token"];
      if (!stepUpToken) {
        return {
          error: "Step-up authorization required",
          requires_step_up: true,
          message:
            "Write operations require an X-Step-Up-Token. Provide authorization to proceed.",
        };
      }
    }

    // Build forwarded headers (tenant, auth, agent)
    const fwdHeaders: Record<string, string> = {
      "Content-Type": "application/fhir+json",
    };
    if (headers?.["x-tenant-id"]) fwdHeaders["X-Tenant-Id"] = headers["x-tenant-id"];
    if (headers?.["x-step-up-token"]) fwdHeaders["X-Step-Up-Token"] = headers["x-step-up-token"];
    if (headers?.["x-agent-id"]) fwdHeaders["X-Agent-Id"] = headers["x-agent-id"];
    if (headers?.["authorization"]) fwdHeaders["Authorization"] = headers["authorization"];

    switch (toolName) {
      case "context.get":
        return this.getContext(input.context_id as string, fwdHeaders);

      case "fhir.read":
        return this.readResource(
          input.resource_type as string,
          input.resource_id as string,
          fwdHeaders
        );

      case "fhir.search":
        return this.searchResources(
          input.resource_type as string,
          input.patient as string | undefined,
          Math.min((input._count as number) || 20, MAX_RESULT_ENTRIES),
          fwdHeaders
        );

      case "fhir.validate":
        return this.validateResource(input.resource as Record<string, unknown>, fwdHeaders);

      case "fhir.propose_write":
        return this.proposeWrite(
          input.resource as Record<string, unknown>,
          input.operation as string,
          fwdHeaders
        );

      case "fhir.commit_write":
        return this.commitWrite(
          input.resource as Record<string, unknown>,
          input.operation as string,
          fwdHeaders
        );

      default:
        return { error: `Unimplemented tool: ${toolName}` };
    }
  }

  async getContext(
    contextId: string,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const resp = await fetch(
      `${this.baseUrl}/context/${encodeURIComponent(contextId)}`,
      { headers }
    );
    if (!resp.ok) {
      return { error: `Context fetch failed with status ${resp.status}` };
    }
    return (await resp.json()) as Record<string, unknown>;
  }

  private async readResource(
    resourceType: string,
    resourceId: string,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const resp = await fetch(
      `${this.baseUrl}/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}`,
      { headers }
    );
    if (!resp.ok) {
      return { error: `Read failed with status ${resp.status}` };
    }
    return (await resp.json()) as Record<string, unknown>;
  }

  private async searchResources(
    resourceType: string,
    patient: string | undefined,
    count: number,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const params = new URLSearchParams();
    if (patient) params.set("patient", patient);
    params.set("_count", count.toString());

    const resp = await fetch(
      `${this.baseUrl}/${encodeURIComponent(resourceType)}?${params.toString()}`,
      { headers }
    );
    if (!resp.ok) {
      return { error: `Search failed with status ${resp.status}` };
    }
    return (await resp.json()) as Record<string, unknown>;
  }

  private async validateResource(
    resource: Record<string, unknown>,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const resourceType = resource.resourceType as string;
    if (!resourceType) {
      return { error: "Resource must have a resourceType" };
    }
    const resp = await fetch(
      `${this.baseUrl}/${encodeURIComponent(resourceType)}/$validate`,
      {
        method: "POST",
        headers,
        body: JSON.stringify(resource),
      }
    );
    if (!resp.ok) {
      return { error: `Validation request failed with status ${resp.status}` };
    }
    return (await resp.json()) as Record<string, unknown>;
  }

  private async proposeWrite(
    resource: Record<string, unknown>,
    operation: string,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const validation = await this.validateResource(resource, headers);
    return {
      operation,
      validation,
      requires_step_up: true,
      message:
        "Resource validated. Provide X-Step-Up-Token to commit this write.",
    };
  }

  private async commitWrite(
    resource: Record<string, unknown>,
    operation: string,
    headers: Record<string, string>
  ): Promise<Record<string, unknown>> {
    const resourceType = resource.resourceType as string;
    if (!resourceType) {
      return { error: "Resource must have a resourceType" };
    }

    let resp;
    if (operation === "create") {
      resp = await fetch(`${this.baseUrl}/${encodeURIComponent(resourceType)}`, {
        method: "POST",
        headers,
        body: JSON.stringify(resource),
      });
    } else if (operation === "update") {
      const resourceId = resource.id as string;
      if (!resourceId) {
        return { error: "Resource ID required for update" };
      }
      resp = await fetch(
        `${this.baseUrl}/${encodeURIComponent(resourceType)}/${encodeURIComponent(resourceId)}`,
        {
          method: "PUT",
          headers,
          body: JSON.stringify(resource),
        }
      );
    } else {
      return { error: `Unknown operation: ${operation}` };
    }

    return (await resp.json()) as Record<string, unknown>;
  }
}
