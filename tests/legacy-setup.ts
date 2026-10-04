// Existing regression suites exercise the explicitly supported legacy contract.
// Strict-mode tests override this switch and test the production default.
process.env.CLAUDE_CODE_MCP_SECURITY_MODE = "legacy";
