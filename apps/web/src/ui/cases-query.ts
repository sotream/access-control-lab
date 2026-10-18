import { LEVELS, rank } from "./components";

export interface Row {
  id: string;
  title: string;
  classification: string;
  unit: string;
  status: string;
  compartments: string[];
  version: number;
}

export const SORTS = ["title", "classification", "unit", "status"] as const;
export type SortKey = (typeof SORTS)[number];
export const STATUS_VALUES = ["draft", "submitted", "approved"] as const;
export const PAGE_SIZE = 25;

export interface Query {
  q: string;
  status: string;
  level: string;
  unit: string;
  sort: SortKey;
  dir: "asc" | "desc";
  page: number;
}

const one = (v: string | string[] | undefined): string => (typeof v === "string" ? v : "");

/** Query-string values are matched against fixed lists or length-bounded; nothing is reflected unvalidated. */
export function parseQuery(raw: Record<string, string | string[] | undefined>): Query {
  const sort = one(raw.sort);
  const page = Number(one(raw.page));
  return {
    q: one(raw.q).slice(0, 100),
    status: (STATUS_VALUES as readonly string[]).includes(one(raw.status)) ? one(raw.status) : "",
    level: (LEVELS as readonly string[]).includes(one(raw.cls)) ? one(raw.cls) : "",
    unit: one(raw.unit).slice(0, 64),
    sort: (SORTS as readonly string[]).includes(sort) ? (sort as SortKey) : "title",
    dir: one(raw.dir) === "desc" ? "desc" : "asc",
    page: Number.isInteger(page) && page >= 1 && page <= 10_000 ? page : 1,
  };
}

const key = (r: Row, k: SortKey): string | number => (k === "classification" ? rank(r.classification) : r[k].toLowerCase());

export function applyQuery(rows: readonly Row[], q: Query): { rows: Row[]; total: number; pages: number } {
  const needle = q.q.toLowerCase();
  const kept = rows.filter((r) => (!needle || r.title.toLowerCase().includes(needle)) && (!q.status || r.status === q.status) && (!q.level || r.classification === q.level) && (!q.unit || r.unit === q.unit));
  const sign = q.dir === "desc" ? -1 : 1;
  kept.sort((a, b) => {
    const x = key(a, q.sort);
    const y = key(b, q.sort);
    return (x < y ? -1 : x > y ? 1 : a.id < b.id ? -1 : 1) * sign;
  });
  const pages = Math.max(1, Math.ceil(kept.length / PAGE_SIZE));
  const page = Math.min(q.page, pages);
  return { rows: kept.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), total: kept.length, pages };
}

/** href for a list state, dropping defaults so URLs stay short (the review queue has its own fixed status) */
export function hrefFor(base: string, q: Query, over: Partial<Query>): string {
  const n = { ...q, ...over };
  const p = new URLSearchParams();
  if (n.q) p.set("q", n.q);
  if (n.status && base !== "/review") p.set("status", n.status);
  if (n.level) p.set("cls", n.level);
  if (n.unit) p.set("unit", n.unit);
  if (n.sort !== "title") p.set("sort", n.sort);
  if (n.dir !== "asc") p.set("dir", n.dir);
  if (n.page > 1) p.set("page", String(n.page));
  const s = p.toString();
  return s ? `${base}?${s}` : base;
}
