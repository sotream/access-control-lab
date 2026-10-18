/**
 * One CSV cell, safe to open in a spreadsheet. A value that starts (after any whitespace) with = + - @ or a tab/CR is a formula to Excel and friends;
 * it is prefixed with an apostrophe so it displays as text. Cells with comma, quote or line break are quoted, quotes doubled.
 */
export function csvCell(value: unknown): string {
  let s = Array.isArray(value) ? value.join(";") : value === null || value === undefined ? "" : String(value);
  if (/^[\s]*[=+\-@]/.test(s) || /^[\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export const csvLine = (cells: readonly unknown[]): string => cells.map(csvCell).join(",");
