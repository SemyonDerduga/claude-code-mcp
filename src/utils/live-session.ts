import type { SDKUserMessage } from "@anthropic-ai/claude-agent-sdk";
import type { SessionManager } from "../session/manager.js";

/** One input slot: replies are accepted only after the previous turn completes. */
export class LiveInput implements AsyncIterableIterator<SDKUserMessage> {
  private pending?: SDKUserMessage;
  private waiter?: (result: IteratorResult<SDKUserMessage>) => void;
  private ended = false;
  send(prompt: string, sessionId: string): void {
    if (this.ended || this.pending) throw new Error("Live input is closed or busy");
    const value: SDKUserMessage = {
      type: "user",
      session_id: sessionId,
      parent_tool_use_id: null,
      message: { role: "user", content: prompt },
    };
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = undefined;
      waiter({ value, done: false });
    } else this.pending = value;
  }
  close(): void {
    this.ended = true;
    this.pending = undefined;
    this.waiter?.({ value: undefined, done: true });
    this.waiter = undefined;
  }
  next(): Promise<IteratorResult<SDKUserMessage>> {
    if (this.pending) {
      const value = this.pending;
      this.pending = undefined;
      return Promise.resolve({ value, done: false });
    }
    if (this.ended) return Promise.resolve({ value: undefined, done: true });
    if (this.waiter) return Promise.reject(new Error("Concurrent live input reader"));
    return new Promise((resolve) => {
      this.waiter = resolve;
    });
  }
  return(): Promise<IteratorResult<SDKUserMessage>> {
    this.close();
    return Promise.resolve({ value: undefined, done: true });
  }
  [Symbol.asyncIterator](): AsyncIterableIterator<SDKUserMessage> {
    return this;
  }
}
export interface LiveSession {
  send: (prompt: string) => void;
  interrupt: () => void;
  close: () => void;
  abortController: AbortController;
}
const sessions = new WeakMap<SessionManager, Map<string, LiveSession>>();
export function getLiveSession(manager: SessionManager, id: string): LiveSession | undefined {
  return sessions.get(manager)?.get(id);
}
export function registerLiveSession(
  manager: SessionManager,
  id: string,
  handle: LiveSession
): void {
  let entries = sessions.get(manager);
  if (!entries) {
    entries = new Map();
    sessions.set(manager, entries);
  }
  entries.set(id, handle);
}
export function removeLiveSession(manager: SessionManager, id: string): void {
  sessions.get(manager)?.delete(id);
}
