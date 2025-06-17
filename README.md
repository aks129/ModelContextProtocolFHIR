This server provides a Model Context Protocol (MCP) interface to interact with FHIR servers.

Overview
The MCP server enables standardized interaction with FHIR (Fast Healthcare Interoperability Resources) servers, providing a unified interface for retrieving and working with healthcare data.

Key Features
Connect to any FHIR API server
Retrieve FHIR resources with read operations
Search FHIR resources with flexible query parameters
View FHIR server metadata and capabilities
Comprehensive error handling and logging

version.01





# 🧠 FHIR Model Context Protocol (MCP) App

**FHIR MCP App** is a developer tool and service that implements the **Model Context Protocol (MCP)** for FHIR. It enables applications, agents, and services to **introspect**, **understand**, and **utilize** healthcare data by querying and resolving its structure, usage context, and intent — with full support for HL7 FHIR profiles and implementation guides.

Think of it as the **FHIR-aware schema registry + documentation engine + semantic resolver** all in one.

---

## 📌 What is MCP?

**Model Context Protocol (MCP)** is a proposed standard for:

* Describing the **context and constraints** of a data model (FHIR or otherwise)
* Providing **machine-readable metadata** about field usage, provenance, rules, relationships, and validation
* Enabling **AI agents**, developer tools, or integration services to dynamically **understand how to use** data models without prior hardcoding

🔗 [Learn more about MCP](https://transformer.health/blog/agentic-context-models)

---

## 🧰 What This App Does

| Capability                  | Description                                                               |
| --------------------------- | ------------------------------------------------------------------------- |
| 📥 FHIR IG Loader           | Imports Implementation Guides from local or remote sources                |
| 🧩 Profile Context Resolver | Builds a complete “context model” from differential + base profile        |
| 📖 API & UI Viewer          | Visualizes the model context for human and machine agents                 |
| 🔄 JSON & OpenAPI Export    | Outputs model context in structured format for use by tools or LLMs       |
| 🤖 Agent Integration        | Built-in endpoints for LLM / agent interaction (e.g., Claude/GPT prompts) |

---

## ⚙️ How It Works

1. **Load a FHIR Implementation Guide** via Simplifier, local upload, or URL
2. **Select a Profile** (e.g., `USCorePatient`)
3. **MCP Resolver** compiles context:

   * Field definitions
   * Value sets & bindings
   * Cardinality, constraints, invariants
   * Provenance & usage notes
   * Real-world usage tips
4. **Expose via REST API** or **generate context prompt** for agents

---

## 📦 Installation

### Prerequisites

* Node.js 18+ or Docker
* Local FHIR IGs or registry access

### Clone & Run

```bash
git clone https://github.com/your-org/fhir-mcp-app.git
cd fhir-mcp-app
npm install
npm run dev
```

or with Docker:

```bash
docker build -t fhir-mcp-app .
docker run -p 3000:3000 fhir-mcp-app
```

---

## 🌐 Example Output (MCP JSON)

```json
{
  "profile": "USCorePatient",
  "fields": [
    {
      "path": "Patient.birthDate",
      "type": "date",
      "description": "The date of birth for the individual",
      "cardinality": "0..1",
      "binding": {
        "strength": "required",
        "valueSet": "http://hl7.org/fhir/ValueSet/us-core-race"
      },
      "usageNotes": "Used for demographics-based risk adjustment"
    }
  ],
  "version": "6.1.0"
}
```

---

## 🧠 Use Cases

* 🧩 Prompt context generation for LLMs (agent-augmented development)
* 🧪 Validation and explainability of field behavior
* 🛠 Tooling support for profile-driven UI or data ingestion engines
* 🧬 Semantic mapping and FHIR model alignment

---

## 🔭 Roadmap

* [ ] SmartGPT + Claude integration via plugins
* [ ] Embed profile diffs and example data
* [ ] Support for multiple FHIR versions
* [ ] Model Context comparison view
* [ ] Bulk MCP generation + ZIP export for IGs

---

## 🤝 Contributing

Open issues, submit pull requests, or propose improvements! This project thrives on community feedback from FHIR, health AI, and dev tool builders.

---

## 👤 Maintainer

Built by **FHIR IQ / Eugene Vestel**
🌐 [https://www.fhiriq.com](https://www.fhiriq.com)
🧠 [FHIR Goats LinkedIn Group](https://www.linkedin.com/groups/12732939/)

---

## 📜 License

Apache 2.0 — open-source and agent-friendly.
