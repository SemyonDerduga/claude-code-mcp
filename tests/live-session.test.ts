import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { SDKMessage, SDKUserMessage } from "@anthropic-ai/claude-agent-sdk";
import { SessionManager } from "../src/session/manager.js";
import { executeClaudeCode } from "../src/tools/claude-code.js";
import { executeClaudeCodeReply } from "../src/tools/claude-code-reply.js";
import { getLiveSession, LiveInput } from "../src/utils/live-session.js";

vi.mock("@anthropic-ai/claude-agent-sdk", () => ({
  query: vi.fn(),
  AbortError: class extends Error {},
}));
import { query } from "@anthropic-ai/claude-agent-sdk";

class FakeOutput implements AsyncIterableIterator<SDKMessage> {
  private values: SDKMessage[] = [];
  private waiter?: {
    resolve: (result: IteratorResult<SDKMessage>) => void;
    reject: (error: Error) => void;
  };
  private ended = false;
  private error?: Error;
  push(value: SDKMessage): void {
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = undefined;
      waiter.resolve({ value, done: false });
    } else this.values.push(value);
  }
  fail(error: Error): void {
    this.error = error;
    this.waiter?.reject(error);
    this.waiter = undefined;
  }
  close = vi.fn(() => {
    this.ended = true;
    this.waiter?.resolve({ value: undefined, done: true });
    this.waiter = undefined;
  });
  interrupt = vi.fn(() => this.push(result("interrupted")));
  next(): Promise<IteratorResult<SDKMessage>> {
    if (this.error) return Promise.reject(this.error);
    if (this.values.length) return Promise.resolve({ value: this.values.shift()!, done: false });
    if (this.ended) return Promise.resolve({ value: undefined, done: true });
    return new Promise((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }
  [Symbol.asyncIterator](): AsyncIterableIterator<SDKMessage> {
    return this;
  }
}
function result(text: string): SDKMessage {
  return {
    type: "result",
    subtype: "success",
    session_id: "live-fixture",
    result: text,
    is_error: false,
    num_turns: 1,
    total_cost_usd: 0,
    duration_ms: 1,
    duration_api_ms: 1,
    usage: {},
    modelUsage: {},
    permission_denials: [],
    stop_reason: null,
    uuid: "fixture",
  } as unknown as SDKMessage;
}

describe("strict in-memory streaming sessions", () => {
  let manager: SessionManager;
  let stream: FakeOutput;
  let root: string;
  let received: SDKUserMessage[];
  beforeEach(() => {
    vi.stubEnv("CLAUDE_CODE_MCP_SECURITY_MODE", undefined);
    root = mkdtempSync(join(tmpdir(), "bridge-live-fixture-"));
    vi.stubEnv("CLAUDE_CODE_MCP_ALLOWED_PROJECT_ROOTS", JSON.stringify([root]));
    manager = new SessionManager();
    stream = new FakeOutput();
    received = [];
    vi.mocked(query).mockImplementation(({ prompt, options }) => {
      expect(options?.persistSession).toBe(false);
      expect(options).not.toHaveProperty("resume");
      expect(typeof prompt).not.toBe("string");
      void (async () => {
        for await (const message of prompt as AsyncIterable<SDKUserMessage>) {
          received.push(message);
          if (received.length === 1)
            stream.push({
              type: "system",
              subtype: "init",
              session_id: "live-fixture",
              tools: [],
              model: "fixture",
              permissionMode: "default",
            } as unknown as SDKMessage);
          if (message.message.content !== "hold")
            stream.push(result(String(message.message.content)));
        }
      })();
      return stream as unknown as ReturnType<typeof query>;
    });
  });
  afterEach(() => {
    manager.destroy();
    vi.unstubAllEnvs();
    vi.clearAllMocks();
  });

  async function start(): Promise<void> {
    const started = await executeClaudeCode({ prompt: "first", cwd: root }, manager, root);
    expect(started.sessionId).toBe("live-fixture");
    await vi.waitFor(() => expect(manager.get("live-fixture")?.status).toBe("idle"));
  }
  it("start → complete → reply uses the same live query with effective metadata", async () => {
    await start();
    expect(manager.toJSON(manager.get("live-fixture")!)).toMatchObject({
      persistSession: false,
      strictMcpConfig: true,
      continuation: "live",
    });
    expect(manager.get("live-fixture")?.settingSources).toEqual([]);
    const reply = await executeClaudeCodeReply(
      { sessionId: "live-fixture", prompt: "second" },
      manager
    );
    expect(reply.status).toBe("running");
    await vi.waitFor(() => expect(manager.getResult("live-fixture")?.result.result).toBe("second"));
    expect(query).toHaveBeenCalledTimes(1);
    expect(received.map((m) => m.message.content)).toEqual(["first", "second"]);
    expect(received[1].session_id).toBe("live-fixture");
  });
  it("interrupts a turn, then accepts another reply; cancellation closes the live process", async () => {
    await start();
    await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "hold" }, manager);
    await vi.waitFor(() => expect(received.length).toBe(2));
    expect(
      await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "concurrent" }, manager)
    ).toMatchObject({ status: "error", error: expect.stringContaining("busy") });
    expect(manager.interrupt("live-fixture")).toBe(true);
    await vi.waitFor(() => expect(manager.get("live-fixture")?.status).toBe("idle"));
    expect(stream.interrupt).toHaveBeenCalledTimes(1);
    expect(getLiveSession(manager, "live-fixture")?.abortController.signal.aborted).toBe(false);
    await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "hold" }, manager);
    expect(manager.cancel("live-fixture")).toBe(true);
    await vi.waitFor(() => expect(manager.get("live-fixture")?.continuation).toBe("expired"));
    expect(
      (await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "late" }, manager)).status
    ).toBe("error");
    expect(query).toHaveBeenCalledTimes(1);
  });
  it.each(["idle", "running"])(
    "transient process failure while %s expires; no hidden disk retry",
    async (state) => {
      await start();
      if (state === "running")
        await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "hold" }, manager);
      stream.fail(new Error("ECONNRESET synthetic failure"));
      await vi.waitFor(() => expect(manager.get("live-fixture")?.continuation).toBe("expired"));
      const reply = await executeClaudeCodeReply(
        { sessionId: "live-fixture", prompt: "new turn" },
        manager
      );
      expect(reply).toMatchObject({
        status: "error",
        error: expect.stringContaining("start a new session"),
      });
      expect(query).toHaveBeenCalledTimes(1);
      expect(stream.close).toHaveBeenCalled();
    }
  );
  it("normal process exit expires and rejects fork/option overrides without querying", async () => {
    await start();
    expect(
      (
        await executeClaudeCodeReply(
          { sessionId: "live-fixture", prompt: "x", forkSession: true },
          manager
        )
      ).status
    ).toBe("error");
    stream.close();
    await vi.waitFor(() => expect(manager.get("live-fixture")?.continuation).toBe("expired"));
    expect(
      (await executeClaudeCodeReply({ sessionId: "live-fixture", prompt: "x" }, manager)).status
    ).toBe("error");
    expect(query).toHaveBeenCalledTimes(1);
  });
  it("deleting or destroying an idle session closes its live input/process", async () => {
    await start();
    const live = getLiveSession(manager, "live-fixture")!;
    expect(manager.delete("live-fixture")).toBe(true);
    expect(live.abortController.signal.aborted).toBe(true);
    await vi.waitFor(() => expect(getLiveSession(manager, "live-fixture")).toBeUndefined());
  });
  it("bounds the input slot and closes waiting readers", async () => {
    const input = new LiveInput();
    input.send("one", "");
    expect(() => input.send("two", "")).toThrow(/busy/);
    expect((await input.next()).value?.message.content).toBe("one");
    const waiting = input.next();
    input.close();
    expect(await waiting).toMatchObject({ done: true });
    expect(() => input.send("late", "")).toThrow(/closed/);
  });
  it("server shutdown closes an idle process without enabling disk persistence", async () => {
    await start();
    const live = getLiveSession(manager, "live-fixture")!;
    manager.destroy();
    expect(live.abortController.signal.aborted).toBe(true);
    await vi.waitFor(() => expect(getLiveSession(manager, "live-fixture")).toBeUndefined());
    expect(stream.close).toHaveBeenCalled();
    expect(query).toHaveBeenCalledTimes(1);
  });
});
