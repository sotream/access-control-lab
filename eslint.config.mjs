import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/.next/**", "**/node_modules/**", "**/next-env.d.ts", "**/coverage/**"] },
  ...tseslint.configs.recommended,
  {
    // No string-built SQL: values reach Postgres only as $n parameters (stage 5, T-14). The same check runs as a test
    // (tests/api-db/src/drift.test.ts) so it cannot be turned off by editing this file alone.
    files: ["apps/api/src/**/*.ts", "apps/web/src/**/*.ts"],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector: "TemplateLiteral[expressions.length>0]:has(TemplateElement[value.raw=/\\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|WHERE|FROM)\\b/i])",
          message: "Do not build SQL with template literals. Use sql`...` with $1 parameters.",
        },
        { selector: "TaggedTemplateExpression[tag.name='sql'][quasi.expressions.length>0]", message: "sql`` accepts no substitutions; pass values as parameters." },
      ],
    },
  },
);
