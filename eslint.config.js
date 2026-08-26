// @ts-check
import tsParser from "@typescript-eslint/parser";
import tsPlugin from "@typescript-eslint/eslint-plugin";

export default [
  {
    ignores: ["**/dist/**", "**/node_modules/**"],
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "@typescript-eslint/no-unused-vars": "warn",
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["**/meidoya/packages/**", "**/meidoya/apps/**", "@meidoya/node-protocol"],
              message:
                "Cross-repository source reads are forbidden (03-repository-boundaries.md section 3). Use packages/node-protocol-client.",
            },
          ],
        },
      ],
    },
  },
];
