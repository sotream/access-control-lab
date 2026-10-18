// The `details` column is deliberately narrow: a fixed set of keys with fixed types. There is no place to put a token, a claim set or free text
// other than the sanitised break-glass justification. The database repeats the key whitelist (audit_details_ok); keep both lists equal.
export const DETAIL_KEYS = ["justification", "alert", "rule_ids", "authoritative", "event", "count", "format", "filters", "from_id", "to_id", "truncated", "acr", "detail_code", "size", "sha256", "media", "scan"] as const;

const TAG = /^[A-Za-z0-9_.:-]{1,64}$/;
const FILTER_KEYS = ["from", "to", "actor", "resource", "action", "effect"];
const MAX_JUSTIFICATION = 500;
const MAX_JSON = 4000;

// controls and bidi overrides are written as code points so that this file itself stays plain text
const isBad = (cp: number) => cp < 0x20 || (cp >= 0x7f && cp <= 0x9f) || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff || cp === 0xad;

/** Free text from a human: control and invisible characters become spaces, whitespace collapses, length is capped. Empty after cleaning: undefined. */
export function sanitizeText(input: unknown, max = MAX_JUSTIFICATION): string | undefined {
  if (typeof input !== "string") return undefined;
  let out = "";
  for (const ch of input) out += isBad(ch.codePointAt(0) as number) ? " " : ch;
  out = out.replace(/\s+/g, " ").trim();
  if (out.length > max) out = [...out].slice(0, max).join("").trim();
  return out === "" ? undefined : out;
}

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown, re: RegExp): v is string => typeof v === "string" && re.test(v);

/** Throws with the offending key on any deviation. Returns the input typed. */
export function validateDetails(d: unknown): Record<string, unknown> {
  if (!isObj(d)) throw new Error("details must be an object");
  for (const [k, v] of Object.entries(d)) {
    switch (k) {
      case "justification":
        if (typeof v !== "string" || v.length < 1 || v.length > MAX_JUSTIFICATION || sanitizeText(v) !== v) throw new Error("details.justification must be sanitised text");
        break;
      case "alert":
      case "authoritative":
      case "truncated":
        if (typeof v !== "boolean") throw new Error(`details.${k} must be boolean`);
        break;
      case "rule_ids":
        if (!Array.isArray(v) || v.length > 20 || !v.every((x) => isStr(x, TAG))) throw new Error("details.rule_ids must be up to 20 tags");
        break;
      case "event":
      case "acr":
      case "detail_code":
        if (!isStr(v, TAG)) throw new Error(`details.${k} must be a tag`);
        break;
      case "size":
        if (!Number.isInteger(v) || (v as number) < 0 || (v as number) > 1_073_741_824) throw new Error("details.size must be a byte count");
        break;
      case "sha256":
        if (!isStr(v, /^[0-9a-f]{64}$/)) throw new Error("details.sha256 must be 64 lowercase hex digits");
        break;
      case "media":
        if (v !== "pdf" && v !== "png" && v !== "jpeg" && v !== "text") throw new Error("details.media must be pdf, png, jpeg or text");
        break;
      case "scan":
        if (!isStr(v, TAG)) throw new Error("details.scan must be a tag");
        break;
      case "format":
        if (v !== "ndjson" && v !== "csv") throw new Error("details.format must be ndjson or csv");
        break;
      case "count":
      case "from_id":
      case "to_id":
        if (!Number.isInteger(v) || (v as number) < 0 || (v as number) > Number.MAX_SAFE_INTEGER) throw new Error(`details.${k} must be a non-negative integer`);
        break;
      case "filters":
        if (!isObj(v) || !Object.keys(v).every((f) => FILTER_KEYS.includes(f)) || !Object.values(v).every((x) => typeof x === "string" && x.length <= 64 && sanitizeText(x, 64) === x)) throw new Error("details.filters must hold up to six short strings");
        break;
      default:
        throw new Error(`details.${k} is not an allowed key`);
    }
  }
  if (JSON.stringify(d).length > MAX_JSON) throw new Error("details too large");
  return d;
}
