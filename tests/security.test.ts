import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildOptions } from "../src/utils/build-options.js";
import {
  assertProjectPath,
  assertToolInput,
  redactOutput,
  redactText,
  safeEnvironment,
  strictSecurity,
} from "../src/utils/security.js";
import { SessionManager } from "../src/session/manager.js";
import { spawn } from "node:child_process";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

describe("strict server policy (no real Claude or credentials)", () => {
  let root: string;
  beforeEach(() => {
    vi.stubEnv("CLAUDE_CODE_MCP_SECURITY_MODE", undefined);
    root = mkdtempSync(join(tmpdir(), "bridge-security-"));
    vi.stubEnv("CLAUDE_CODE_MCP_ALLOWED_PROJECT_ROOTS", JSON.stringify([root]));
  });
  afterEach(() => vi.unstubAllEnvs());

  it("fails closed by default without operator roots", () => {
    expect(strictSecurity()).toBe(true);
    vi.stubEnv("CLAUDE_CODE_MCP_ALLOWED_PROJECT_ROOTS", undefined);
    expect(() => buildOptions({ cwd: root })).toThrow(/roots/);
  });
  it("never inherits injected secrets or runtime/proxy configuration", () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "sk-ant-canary-not-real-123456");
    vi.stubEnv("PRIVATE_SECRET", "canary-private");
    vi.stubEnv("NODE_OPTIONS", "--require malicious.js");
    vi.stubEnv("HTTPS_PROXY", "https://bad.invalid");
    expect(safeEnvironment()).not.toHaveProperty("ANTHROPIC_API_KEY");
    const options = buildOptions({ cwd: root });
    expect(JSON.stringify(options.env)).not.toMatch(/canary|malicious|bad.invalid/);
    expect(options.tools).toEqual([]);
    expect(options.persistSession).toBe(false);
    expect(options.settingSources).toEqual([]);
    expect(options.strictMcpConfig).toBe(true);
    expect(options.mcpServers).toEqual({});
  });
  it("pins the Node runtime without executing a process in this test", () => {
    const options = buildOptions({ cwd: root });
    const signal = new AbortController().signal;
    options.spawnClaudeCodeProcess!({
      command: "node",
      args: ["fixture-cli.js"],
      cwd: root,
      env: options.env!,
      signal,
    });
    expect(spawn).toHaveBeenCalledWith(
      process.execPath,
      ["fixture-cli.js"],
      expect.objectContaining({ env: options.env, signal })
    );
    expect(() =>
      options.spawnClaudeCodeProcess!({ command: "malicious-runtime", args: [], env: {}, signal })
    ).toThrow(/unexpected runtime/);
  });
  it.each([
    "env",
    "settings",
    "mcpServers",
    "agents",
    "agent",
    "sandbox",
    "toolConfig",
    "debugFile",
    "pathToClaudeCodeExecutable",
  ])("rejects caller override %s", (key) => {
    expect(() =>
      buildOptions({ cwd: root, [key]: {} } as Parameters<typeof buildOptions>[0])
    ).toThrow(/forbidden/);
  });
  it("rejects preset tools, preapproval, persistence and external settings", () => {
    for (const override of [
      { tools: ["Bash"] },
      { allowedTools: ["Read"] },
      { persistSession: true },
      { debug: true },
      { strictMcpConfig: false },
      { settingSources: ["user"] },
    ]) {
      expect(() =>
        buildOptions({ cwd: root, ...override } as Parameters<typeof buildOptions>[0])
      ).toThrow(/Security policy/);
    }
  });
  it("rejects traversal, sibling prefixes, external directories and symlink escapes", () => {
    const outside = mkdtempSync(join(tmpdir(), "bridge-outside-"));
    writeFileSync(join(outside, "file"), "public fixture");
    symlinkSync(outside, join(root, "link"));
    symlinkSync(join(outside, "missing"), join(root, "dangling"));
    for (const path of [
      outside,
      `${root}-sibling`,
      join(root, "..", "escape"),
      join(root, "link", "file"),
      join(root, "link", "new"),
      join(root, "dangling"),
    ]) {
      expect(() => assertProjectPath(path)).toThrow();
    }
    expect(() => buildOptions({ cwd: root, additionalDirectories: [outside] })).toThrow();
    mkdirSync(join(root, "sub"));
    expect(assertProjectPath(join(root, "sub", "new"))).toBe(
      join(realpathSync(root), "sub", "new")
    );
  });
  it("blocks protected stores and unknown/command tools", () => {
    for (const path of [
      ".env",
      ".env.local",
      ".claude/projects/file",
      ".codex/sessions/file",
      ".ssh/id_rsa",
    ]) {
      expect(() => assertToolInput("Read", { file_path: path }, root)).toThrow();
    }
    for (const tool of ["Bash", "Glob", "Grep", "Task", "mcp__evil__tool"]) {
      expect(() => assertToolInput(tool, { file_path: "file" }, root)).toThrow();
    }
  });
  it("uses a deny/ask pre-tool hook even for normally autoallowed reads", async () => {
    const options = buildOptions({ cwd: root, tools: ["Read"] });
    const hook = options.hooks!.PreToolUse![0].hooks[0];
    const base = {
      hook_event_name: "PreToolUse" as const,
      session_id: "mock",
      transcript_path: "unused",
      cwd: root,
      tool_use_id: "mock",
      tool_name: "Read",
    };
    const safe = await hook({ ...base, tool_input: { file_path: join(root, "new") } }, "mock", {
      signal: new AbortController().signal,
    });
    expect(safe).toMatchObject({ hookSpecificOutput: { permissionDecision: "ask" } });
    const unsafe = await hook({ ...base, tool_input: { file_path: "/outside" } }, "mock", {
      signal: new AbortController().signal,
    });
    expect(unsafe).toMatchObject({ hookSpecificOutput: { permissionDecision: "deny" } });
  });
  it("revalidates changed permission input and cancels pending approvals", async () => {
    const manager = new SessionManager();
    const controller = new AbortController();
    manager.create({ sessionId: "mock", cwd: root, abortController: controller });
    const finish = vi.fn();
    const record = {
      requestId: "r",
      toolUseID: "mock",
      toolName: "Read",
      input: { file_path: join(root, "new") },
      summary: "fixture",
      createdAt: new Date().toISOString(),
    };
    manager.setPendingPermission("mock", record, finish, 1000);
    manager.finishRequest(
      "mock",
      "r",
      { behavior: "allow", updatedInput: { file_path: "/outside" } },
      "respond"
    );
    expect(finish).toHaveBeenCalledWith(expect.objectContaining({ behavior: "deny" }));
    manager.setPendingPermission("mock", { ...record, requestId: "r2" }, finish, 1000);
    manager.cancel("mock");
    expect(finish).toHaveBeenLastCalledWith(expect.objectContaining({ behavior: "deny" }));
    manager.destroy();
  });
  it("redacts token/log/error/output canaries with bounded limits", () => {
    const token = "sk-ant-canary-not-real-123456";
    const output = {
      error: new Error(`Bearer ${token}`),
      content: [{ text: JSON.stringify({ api_key: "canary-value", result: token }) }],
      access_token: "opaque-canary",
    };
    expect(JSON.stringify(redactOutput(output))).not.toMatch(/canary/);
    expect(redactText("x".repeat(1_000_001))).toContain("oversized");
    // Deliberate limit: unknown unlabeled secrets cannot be inferred from text.
    expect(redactText("opaque-unlabeled-value")).toBe("opaque-unlabeled-value");
  });
});
