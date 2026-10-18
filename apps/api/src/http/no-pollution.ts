import type { NextFunction, Request, Response } from "express";

const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);
const MAX_DEPTH = 20;

/** true when the value holds an own property with one of the prototype-pollution names, at any depth (bounded) */
export function hasPollutingKey(v: unknown, depth = 0): boolean {
  if (depth > MAX_DEPTH) return true; // absurd nesting is refused too
  if (typeof v !== "object" || v === null) return false;
  if (Array.isArray(v)) return v.some((x) => hasPollutingKey(x, depth + 1));
  for (const k of Object.getOwnPropertyNames(v)) if (FORBIDDEN.has(k) || hasPollutingKey((v as Record<string, unknown>)[k], depth + 1)) return true;
  return false;
}

/**
 * JSON.parse makes `__proto__` an ordinary own property, and the validation pipe (class-transformer) drops it silently, so a body such as
 * {"title":"x","__proto__":{"status":"approved"}} would be ACCEPTED as if the key were not there. Nothing is polluted today, but "unknown fields are refused"
 * must hold for these names too, and a library that merges bodies later would turn the silent drop into a hole. Refused with the same 400 as any unknown field.
 */
export function rejectPollutingKeys(req: Request, res: Response, next: NextFunction): void {
  if (req.body !== undefined && hasPollutingKey(req.body)) {
    res.status(400).json({ statusCode: 400, error: "Bad Request" });
    return;
  }
  next();
}
