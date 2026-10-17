import type { LoggerService } from "@nestjs/common";

const SENSITIVE = /authorization|cookie|token|password|passwd|secret|credential|assertion|code_verifier|^code$|api[-_]?key/i;
const MAX_DEPTH = 5;
const MAX_STRING = 300;

/** Deep copy with sensitive keys masked and JWT-looking strings replaced. Safe to call on arbitrary input. */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === "string") {
    if (/^eyJ[\w-]+\.[\w-]+\.[\w-]*$/.test(value)) return "[REDACTED_JWT]";
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}...` : value;
  }
  if (typeof value !== "object" || value === null) return value;
  if (depth >= MAX_DEPTH) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) out[k] = SENSITIVE.test(k) ? "[REDACTED]" : redact(v, depth + 1);
  return out;
}

export type Sink = (line: string) => void;

/** One JSON object per line on stdout. Everything passes through redact(). */
export class JsonLogger implements LoggerService {
  constructor(private readonly sink: Sink = (l) => process.stdout.write(`${l}\n`)) {}

  event(level: "info" | "warn" | "error", msg: string, fields: Record<string, unknown> = {}): void {
    this.sink(JSON.stringify({ time: new Date().toISOString(), level, msg, ...(redact(fields) as object) }));
  }

  // LoggerService (Nest internals and anything that calls Logger)
  log(message: unknown) {
    this.event("info", String(redact(typeof message === "string" ? message : JSON.stringify(redact(message)))));
  }
  warn(message: unknown) {
    this.event("warn", String(redact(typeof message === "string" ? message : JSON.stringify(redact(message)))));
  }
  error(message: unknown) {
    this.event("error", String(redact(typeof message === "string" ? message : JSON.stringify(redact(message)))));
  }
}
