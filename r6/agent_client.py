"""
Enhanced Claude Client for Agent Orchestration.

Supports:
- 1M-token context window via anthropic-beta header
- Prompt caching with cache_control markers
- Tool loop with correct tool_result formatting
- Programmatic tool calling for multi-step workflows
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from anthropic import Anthropic

logger = logging.getLogger(__name__)

# R6 Agent system prompt
R6_AGENT_SYSTEM_PROMPT = """You are a clinical data assistant operating within an R6 FHIR server.
You have access to FHIR tools for reading and searching clinical resources.
You MUST ground all responses in the data returned by your tools.
NEVER fabricate clinical data. If you cannot find relevant data, say so.
When proposing writes, always call $validate first and present the validation
result to the user before requesting step-up authorization."""

# Tool definitions for the agent
AGENT_TOOLS = [
    {
        "name": "context_get",
        "description": "Retrieve a pre-built context envelope containing patient-centric FHIR resources. Returns demographics, observations, encounters, and consent information within the context window.",
        "input_schema": {
            "type": "object",
            "properties": {
                "context_id": {
                    "type": "string",
                    "description": "The context envelope ID"
                }
            },
            "required": ["context_id"]
        }
    },
    {
        "name": "fhir_read",
        "description": "Read a specific FHIR R6 resource by type and ID.",
        "input_schema": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "description": "The FHIR resource type (e.g., Patient, Observation)",
                    "enum": ["Patient", "Encounter", "Observation", "AuditEvent", "Consent"]
                },
                "resource_id": {
                    "type": "string",
                    "description": "The resource ID"
                }
            },
            "required": ["resource_type", "resource_id"]
        }
    },
    {
        "name": "fhir_search",
        "description": "Search for FHIR R6 resources with basic parameters. Returns a Bundle of matching resources.",
        "input_schema": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "description": "The FHIR resource type to search",
                    "enum": ["Patient", "Encounter", "Observation", "AuditEvent", "Consent"]
                },
                "patient": {
                    "type": "string",
                    "description": "Patient reference to filter by (e.g., Patient/123)"
                },
                "count": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 50
                }
            },
            "required": ["resource_type"]
        }
    },
    {
        "name": "fhir_validate",
        "description": "Validate a proposed FHIR R6 resource against the R6 specification. Returns an OperationOutcome with validation issues.",
        "input_schema": {
            "type": "object",
            "properties": {
                "resource": {
                    "type": "object",
                    "description": "The FHIR resource to validate"
                }
            },
            "required": ["resource"]
        }
    },
    {
        "name": "fhir_propose_write",
        "description": "Propose a write to a FHIR R6 resource. This validates the resource and returns a preview. Requires step-up authorization to commit.",
        "input_schema": {
            "type": "object",
            "properties": {
                "resource": {
                    "type": "object",
                    "description": "The FHIR resource to write"
                },
                "operation": {
                    "type": "string",
                    "enum": ["create", "update"],
                    "description": "The write operation type"
                }
            },
            "required": ["resource", "operation"]
        }
    }
]


class AgentClient:
    """Claude-powered agent client with tool loop support."""

    def __init__(self, api_key=None, enable_1m_context=False):
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        self.client = None
        self.enable_1m_context = enable_1m_context
        self.model = 'claude-opus-4-6'
        self._initialize()

    def _initialize(self):
        """Initialize the Anthropic client."""
        if self.api_key:
            try:
                self.client = Anthropic(api_key=self.api_key)
                logger.info('AgentClient initialized')
            except Exception as e:
                logger.error(f'Failed to initialize AgentClient: {e}')

    def is_configured(self):
        return self.client is not None

    def run_agent_loop(self, user_message, context_id=None,
                       tool_executor=None, max_turns=10):
        """
        Run an agent tool loop with Claude.

        The agent receives the user message and can call tools.
        The loop continues until Claude stops requesting tools
        or max_turns is reached.

        Args:
            user_message: The user's question or instruction
            context_id: Optional context envelope ID for grounding
            tool_executor: Callable(tool_name, tool_input) -> tool_result
            max_turns: Maximum number of tool-use round trips

        Returns:
            dict with 'response', 'tool_calls', 'token_usage'
        """
        if not self.is_configured():
            raise RuntimeError('AgentClient not configured')

        messages = [{"role": "user", "content": user_message}]
        tool_calls_log = []
        total_input_tokens = 0
        total_output_tokens = 0

        # Build request kwargs
        create_kwargs = self._build_request_kwargs()

        for turn in range(max_turns):
            create_kwargs_turn = {
                **create_kwargs,
                "messages": messages,
            }

            response = self.client.messages.create(**create_kwargs_turn)

            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            # Check if the model wants to use tools
            if response.stop_reason == 'tool_use':
                # Process tool calls
                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                tool_results = []
                for block in assistant_content:
                    if block.type == 'tool_use':
                        tool_name = block.name
                        tool_input = block.input
                        tool_id = block.id

                        logger.debug(f'Agent tool call: {tool_name}({json.dumps(tool_input)[:200]})')

                        # Execute the tool
                        if tool_executor:
                            try:
                                result = tool_executor(tool_name, tool_input)
                            except Exception as e:
                                result = {"error": str(e)}
                        else:
                            result = {"error": "No tool executor configured"}

                        tool_calls_log.append({
                            'tool': tool_name,
                            'input': tool_input,
                            'output_preview': str(result)[:500]
                        })

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": json.dumps(result) if isinstance(result, dict) else str(result)
                        })

                messages.append({"role": "user", "content": tool_results})
            else:
                # Model finished - extract text response
                text_parts = [
                    block.text for block in response.content
                    if hasattr(block, 'text')
                ]
                final_response = '\n'.join(text_parts)

                return {
                    'response': final_response,
                    'tool_calls': tool_calls_log,
                    'turns': turn + 1,
                    'token_usage': {
                        'input_tokens': total_input_tokens,
                        'output_tokens': total_output_tokens,
                        'total_tokens': total_input_tokens + total_output_tokens
                    }
                }

        # Max turns reached
        return {
            'response': '[Agent reached maximum turns without completing]',
            'tool_calls': tool_calls_log,
            'turns': max_turns,
            'token_usage': {
                'input_tokens': total_input_tokens,
                'output_tokens': total_output_tokens,
                'total_tokens': total_input_tokens + total_output_tokens
            }
        }

    def _build_request_kwargs(self):
        """Build the request kwargs for Claude API calls."""
        kwargs = {
            "model": self.model,
            "max_tokens": 4096,
            "tools": AGENT_TOOLS,
        }

        # System prompt with cache_control for prompt caching
        kwargs["system"] = [
            {
                "type": "text",
                "text": R6_AGENT_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"}
            }
        ]

        # 1M context beta header
        if self.enable_1m_context:
            kwargs["extra_headers"] = {
                "anthropic-beta": "context-1m-2025-08-07"
            }

        return kwargs

    def create_tool_executor(self, app, base_url='http://localhost:5000'):
        """
        Create a tool executor function that calls the R6 FHIR endpoints.

        Args:
            app: Flask app instance (for app context)
            base_url: Base URL of the FHIR server

        Returns:
            Callable tool executor
        """
        import requests as http_requests

        def executor(tool_name, tool_input):
            if tool_name == 'context_get':
                resp = http_requests.get(
                    f'{base_url}/r6/fhir/context/{tool_input["context_id"]}'
                )
                return resp.json()

            elif tool_name == 'fhir_read':
                resp = http_requests.get(
                    f'{base_url}/r6/fhir/{tool_input["resource_type"]}/{tool_input["resource_id"]}'
                )
                return resp.json()

            elif tool_name == 'fhir_search':
                params = {}
                if 'patient' in tool_input:
                    params['patient'] = tool_input['patient']
                if 'count' in tool_input:
                    params['_count'] = tool_input['count']
                resp = http_requests.get(
                    f'{base_url}/r6/fhir/{tool_input["resource_type"]}',
                    params=params
                )
                return resp.json()

            elif tool_name == 'fhir_validate':
                resource = tool_input['resource']
                resource_type = resource.get('resourceType', 'Patient')
                resp = http_requests.post(
                    f'{base_url}/r6/fhir/{resource_type}/$validate',
                    json=resource
                )
                return resp.json()

            elif tool_name == 'fhir_propose_write':
                resource = tool_input['resource']
                resource_type = resource.get('resourceType', 'Patient')
                # First validate
                val_resp = http_requests.post(
                    f'{base_url}/r6/fhir/{resource_type}/$validate',
                    json=resource
                )
                validation = val_resp.json()
                return {
                    'operation': tool_input.get('operation', 'create'),
                    'validation': validation,
                    'requires_step_up': True,
                    'message': 'Resource validated. Step-up authorization required to commit.'
                }

            else:
                return {"error": f"Unknown tool: {tool_name}"}

        return executor
