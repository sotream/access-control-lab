/**
 * Test helpers, not part of the package API: a small RFC 4180 reader (quoted cells may hold commas, doubled quotes and line breaks) and the
 * predicate for "this cell would be a formula in a spreadsheet". Used by the unit test of the exporter and by the attack suite.
 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"' && cell === "") quoted = true;
    else if (c === ",") {
      row.push(cell);
      cell = "";
    } else if (c === "\n" || (c === "\r" && text[i + 1] === "\n")) {
      if (c === "\r") i++;
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else cell += c;
  }
  if (cell !== "" || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

/** A cell the exporter has NOT neutralised: it starts, after optional whitespace, with = + - @, or starts with a tab or CR. A leading apostrophe is the neutralised form. */
export const isRawFormula = (cell: string): boolean => !cell.startsWith("'") && (/^\s*[=+\-@]/.test(cell) || /^[\t\r]/.test(cell));
