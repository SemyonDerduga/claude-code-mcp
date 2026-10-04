import { existsSync, lstatSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { OptionSource } from "./build-options.js";

/** Legacy mode is an explicit compatibility escape hatch, never a sandbox. */
export function strictSecurity(): boolean {
  return process.env.CLAUDE_CODE_MCP_SECURITY_MODE !== "legacy";
}

export function safeEnvironment(): Record<string, string> {
  const env: Record<string, string> = {};
  // PATH/HOME and auth/proxy/Node injection variables are intentionally absent.
  for (const key of ["LANG", "LC_ALL", "TZ", "SYSTEMROOT", "WINDIR"]) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  return env;
}

function roots(): string[] {
  const raw = process.env.CLAUDE_CODE_MCP_ALLOWED_PROJECT_ROOTS;
  if (!raw) throw new Error("Security policy: allowed project roots are required");
  const parsed: unknown = JSON.parse(raw);
  if (
    !Array.isArray(parsed) ||
    parsed.length === 0 ||
    parsed.some((p) => typeof p !== "string" || !isAbsolute(p))
  ) {
    throw new Error("Security policy: roots must be a nonempty JSON array of absolute directories");
  }
  return parsed.map((p: string) => {
    const canonical = realpathSync(p);
    if (!statSync(canonical).isDirectory() || dirname(canonical) === canonical) {
      throw new Error("Security policy: root must be a project directory");
    }
    return canonical;
  });
}

/** Resolve existing ancestors, including symlinks, before testing containment. */
export function assertProjectPath(path: string, cwd?: string, directory = false): string {
  if (!path || path.includes("\0")) throw new Error("Security policy: invalid path");
  const absolute = resolve(cwd ?? process.cwd(), path);
  let ancestor = absolute;
  const tail: string[] = [];
  while (true) {
    try {
      lstatSync(ancestor);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const parent = dirname(ancestor);
    if (parent === ancestor) throw new Error("Security policy: inaccessible path");
    tail.unshift(relative(parent, ancestor));
    ancestor = parent;
  }
  const canonical = resolve(realpathSync(ancestor), ...tail);
  const contained = roots().some((root) => {
    const suffix = relative(root, canonical);
    return (
      suffix === "" || (!isAbsolute(suffix) && suffix !== ".." && !suffix.startsWith(`..${sep}`))
    );
  });
  if (!contained) throw new Error("Security policy: path outside allowed roots");
  if (directory && (!existsSync(canonical) || !statSync(canonical).isDirectory())) {
    throw new Error("Security policy: directory must exist");
  }
  if (
    canonical
      .split(/[\\/]/)
      .some((part) =>
        /^(?:\.env(?:\..*)?|\.credentials\.json|\.ssh|\.aws|\.codex|\.claude)$/i.test(part)
      )
  ) {
    throw new Error("Security policy: protected storage path");
  }
  return canonical;
}

const fileTools = ["Read", "Write", "Edit"];

export function assertToolInput(tool: string, input: unknown, cwd: string): void {
  if (!strictSecurity()) return;
  if (!fileTools.includes(tool) || !input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Security policy: tool is not enabled in strict mode");
  }
  const path = (input as Record<string, unknown>).file_path;
  if (typeof path !== "string") throw new Error("Security policy: file_path is required");
  assertProjectPath(path, cwd);
}

export function assertRequestOptions(src: OptionSource): void {
  if (!strictSecurity()) return;
  assertProjectPath(src.cwd, undefined, true);
  for (const path of src.additionalDirectories ?? []) assertProjectPath(path, src.cwd, true);
  for (const key of [
    "env",
    "settings",
    "mcpServers",
    "agents",
    "agent",
    "sandbox",
    "toolConfig",
    "debugFile",
    "pathToClaudeCodeExecutable",
  ] as const) {
    if (src[key] !== undefined) throw new Error(`Security policy: caller ${key} is forbidden`);
  }
  if (
    src.debug ||
    src.persistSession ||
    src.enableFileCheckpointing ||
    src.strictMcpConfig === false ||
    (src.settingSources?.length ?? 0) > 0
  ) {
    throw new Error("Security policy: persistence, debug and external configuration are disabled");
  }
  if (
    src.tools !== undefined &&
    (!Array.isArray(src.tools) || src.tools.some((tool) => !fileTools.includes(tool)))
  ) {
    throw new Error("Security policy: only Read, Write and Edit may be enabled");
  }
  if ((src.allowedTools?.length ?? 0) > 0)
    throw new Error("Security policy: preapproved tools are forbidden");
}

/** Bounded pattern redaction, not a detector for arbitrary/encoded secrets. */
export function redactText(text: string): string {
  if (text.length > 1_000_000) return "[REDACTED: oversized output]";
  return text
    .replace(
      /\b(?:sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[A-Z0-9]{16})\b/g,
      "[REDACTED]"
    )
    .replace(/(\bBearer\s+)[A-Za-z0-9._~+/-]+/gi, "$1[REDACTED]")
    .replace(
      /((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*["']?\s*[:=]\s*["']?)[^\s,"'\\}\]]+/gi,
      "$1[REDACTED]"
    );
}

export function redactOutput(value: unknown, depth = 0): unknown {
  if (depth > 32) return "[REDACTED: depth limit]";
  if (typeof value === "string") return redactText(value);
  if (value instanceof Error) return redactText(value.message);
  if (Array.isArray(value))
    return value.length > 10_000
      ? "[REDACTED: array limit]"
      : value.map((v) => redactOutput(v, depth + 1));
  if (value && typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length > 10_000) return "[REDACTED: object limit]";
    return Object.fromEntries(
      entries.map(([key, v]) => [
        key,
        /^(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)$/i.test(
          key
        )
          ? "[REDACTED]"
          : redactOutput(v, depth + 1),
      ])
    );
  }
  return value;
}
