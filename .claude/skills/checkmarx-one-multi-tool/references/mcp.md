# Checkmarx One MCP Reference

Checkmarx exposes its platform over the Model Context Protocol (MCP), so an AI
assistant can query and act on Checkmarx data in natural language. Relevant when
the user wants to explore findings/posture conversationally rather than run the
Multi-Tool's deterministic scripts.

Docs: https://docs.checkmarx.com/en/34965-591689-mcp-server---interacting-with-checkmarx-via-ai-assistant.html
Product: https://checkmarx.com/solutions/checkmarx-mcp/

## What the MCP covers

- Trigger scans (sast/sca/kics/apisec/secrets/containers) of a repo/dir/image.
- Retrieve and filter findings across engines; drill into a finding's data flow.
- Query posture across projects/applications ("riskiest app this week").
- Remediation guidance (Dev Assist) inside IDEs.
- ~20 high-level, composable tools designed for natural-language/agent use.
- Enterprise controls: SSO, RBAC passthrough, tenant isolation, audit logging.

Two surfaces exist: the IDE-bound **Dev Assist** MCP (detection + AI remediation,
needs a Checkmarx One Assist license, enabled by an admin under Settings > Plugins),
and a **hosted MCP server** connectable from Claude/Cursor/VS Code/etc.

## What the MCP does NOT cover

Tenant administration: creating users/groups/roles, onboarding repos, creating
applications, presets, policies, or teardown. Those remain the Multi-Tool's job.

## When to use which

| Goal | Best tool |
|---|---|
| "Stand up / tear down a demo tenant" | Multi-Tool (this skill) |
| "Onboard these repos / create these users" | Multi-Tool |
| "Make results look realistically triaged" | Multi-Tool `triage-simulate` (weighted rolls) |
| "What are my critical findings / riskiest app?" | Checkmarx MCP (if connected) |
| "Scan this repo and show the data flow" | Checkmarx MCP or `cx` CLI |

## Note

The MCP and Assist surface evolve quickly and parts are license-gated. If a user
asks to use it, check current availability and connection status in their tenant
rather than assuming; this skill does not depend on the MCP being present.
