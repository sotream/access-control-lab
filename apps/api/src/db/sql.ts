// The only way to write SQL in this codebase: a tagged template that accepts NO substitutions.
// `sql`SELECT ... ${x}`` fails to typecheck (args are `never`) and throws at runtime, so values can only travel as
// $1, $2 parameters. An ESLint rule and tests/api-db/src/drift.test.ts also forbid SQL-looking template literals elsewhere.
declare const brand: unique symbol;
export type Sql = string & { readonly [brand]: true };

export function sql(strings: TemplateStringsArray, ...noValues: never[]): Sql {
  if (strings.length !== 1 || noValues.length !== 0) throw new Error("sql`` does not accept substitutions; use $1 parameters");
  return strings[0] as Sql;
}
