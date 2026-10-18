const MAP: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

/** HTML-escapes text for the few places where a route handler writes markup itself (React pages escape by default). */
export const esc = (s: unknown): string => String(s).replace(/[&<>"'`]/g, (c) => MAP[c] as string);
