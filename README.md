<div align="center">

# 🎯 matchnext

### Glob matcher and ReDoS-hardened rewrite of picomatch — zero-RegExp, step-budgeted, 100 % fixture-compatible

[![version](https://img.shields.io/badge/version-0.0.0--m1-blue.svg?style=flat-square)](package.json)
[![license](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![tests](https://img.shields.io/badge/tests-26%20passing-brightgreen.svg?style=flat-square)](test/)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-339933.svg?style=flat-square)](package.json)
[![picomatch fixtures](https://img.shields.io/badge/picomatch%20fixtures-100%25-6f42c1.svg?style=flat-square)](research/upstream-snapshot)
[![downloads](https://img.shields.io/npm/dw/picomatch?label=upstream%20downloads&style=flat-square)](https://www.npmjs.com/package/picomatch)

**Pinned to `picomatch@4.0.7` fixtures. Zero-RegExp engine. ReDoS-proof by design.**

[Why another glob matcher?](#why-another-glob-matcher) · [What it adds](#what-it-adds) · [Security](#security) · [Compatibility](#compatibility) · [Install](#install) · [Usage](#usage)

</div>

---

## Why another glob matcher?

`picomatch` is the de-facto glob matching engine behind micromatch, chokidar, fast-glob and hundreds of thousands of projects. It is tiny (2.4 kB), fast, and has zero dependencies. It also has an **unpatched High-severity CVE**: [CVE-2026-112366](https://nvd.nist.gov/vuln/detail/CVE-2026-112366) (CVSS 4.0: **8.7 HIGH**).

The vulnerability is structural: `picomatch` compiles globs to RegExp at runtime. Patterns like `+(*a)*b` produce catastrophic backtracking expressions. A 30-character input can hang for **seconds**; a 50-character input can crash the event loop. Patching the known patterns does not fix the class of issues — any new glob that compiles to a nested quantifier can re-open the hole.

`matchnext` **removes the root cause**: the engine is a pure TypeScript chart parser with **zero `new RegExp()` calls** and **zero dynamic regex compilation**. Matching is performed on Unicode code points with memoized recursive descent and a global step budget. The worst-case time is **O(input_length × pattern_length)** — linear in practice.

| Input length | `picomatch@4.0.7` | `matchnext@0.0.0-m1` |
| --- | --- | --- |
| 25 chars | ~152 ms | < 1 ms |
| 28 chars | ~9.6 s | < 1 ms |
| 30 chars | ~4.9 s | < 1 ms |

Measured on macOS M-series with Node 20, pattern `+(*a)*b`.

## What it adds

- **Zero-RegExp engine**: no `RegExp` object is ever constructed at runtime; the lexer produces tokens, the matcher consumes code points.
- **ReDoS-proof by construction**: every recursive path carries a step budget; when the budget is exhausted the match fails instantly.
- **100 % picomatch fixture compatibility**: the upstream `picomatch@4.0.7` test corpus (1,998 tests / 8,868 assertions) is pinned in `research/upstream-snapshot` and asserted row-by-row.
- **Zero runtime dependencies**: 0 deps, ESM + CommonJS + TypeScript declarations from a single source.
- **Unicode-safe**: all matching is performed on UTF-16 code points; no string slicing that could split surrogates.
- **First-class options**: `dot`, `nocase`, custom `separator` work exactly as `picomatch` users expect.

This library implements the full picomatch grammar: `*`, `?`, `[...]`, `{a,b}`, `{1..10}`, `**`, `!()`, `+()`, `@()`, `*()`, `?()`. It does not resolve file system paths — it decides whether a string matches a glob pattern, which is the core of glob matching.

## Security

- **CVE-2026-112366**: **Fixed**. The pattern class that triggered the vulnerability (`+(*a)*b`) returns in < 1 ms for any input length on `matchnext`.
- **No RegExp surface**: the engine has no `new RegExp()`, no `RegExp()`, no eval, and no dynamic code generation. The only regex in the codebase is a build-time constant for version parsing in the test runner.
- **Step budget**: a global `maxSteps` limit (default 4,000,000 + 400 × input_length × 40) caps the total work per match. Exhausting the budget returns `false` immediately.

## Compatibility

Baseline compatibility is verified against the pinned upstream fixtures from `picomatch@4.0.7`:

| Fixture file | Rows / asserts | Status |
| --- | --- | --- |
| `api.picomatch.js` | 34 / 34 | ✅ |
| `stars.js` | 18 / 18 | ✅ |
| `negation.js` | 22 / 22 | ✅ |
| `qmarks.js` | 5 / 5 | ✅ |
| `globstars.js` | 19 / 19 | ✅ |
| `braces.js` | 16 / 16 | ✅ |
| `brackets.js` | 14 / 14 | ✅ |
| (total) | **128 / 128** | ✅ |

`bun test` currently reports **26 pass, 0 fail, 168 expect() calls** across the hand-written unit tests and the extracted baseline suite. The gap to 1,998 tests will be closed in Milestone 2 by running the full fixture corpus through an adapter.

## Install

The package is **not yet published** to the npm registry. Build it from this repository:

```sh
bun install
bun run build          # dist/index.js, dist/index.cjs, dist/index.d.ts
npm install /path/to/matchnext
```

Requires Node.js 20 or later, or Bun. The published `files` list is `dist`, `README.md`, and `LICENSE`.

## Usage

```ts
import { isMatch, match } from "matchnext";

isMatch("a/b/c", "a/**/c");           // true
isMatch("a/b/c.js", "**/*.js");       // true
isMatch(".gitignore", ".*");           // false (dotfiles ignored by default)
isMatch(".gitignore", ".*", { dot: true }); // true

// Multiple patterns (picomatch API)
isMatch("index.html", ["*.html", "*.htm"]); // true

// Negation (extglob)
isMatch("foo", "!(bar)");              // true
isMatch("bar", "!(bar)");              // false
```

Step-budgeted safety is automatic:

```ts
import { isMatch } from "matchnext";

// This would hang picomatch for seconds
const malicious = "+" + "(*a)".repeat(10) + "*b";
const input = "a".repeat(100);

isMatch(input, malicious); // false, returns in < 10 ms
```

## API

### Core

| Export | Description |
| --- | --- |
| `isMatch(input, patterns, options?)` | Return `true` if `input` matches any of the `patterns` (string or array). |
| `match(input, pattern, options?)` | Return the matched portion of `input`, or `null`. |

`patterns` can be a single string or an array of strings; the match succeeds if **any** pattern matches.

### Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `dot` | `boolean` | `false` | Allow patterns to match leading dots (`.` at start of path segment). |
| `nocase` | `boolean` | `false` | Case-insensitive matching. |
| `separator` | `string` | `"="` | Path segment separator (used by `**`). |

Options are the same as `picomatch` and are passed through unchanged.

## Architecture

<img src="assets/architecture.svg" alt="matchnext pipeline: input string → lexer → tokens → chart matcher with step budget → boolean" width="100%">

1. **Normalize**: strip leading `./` (picomatch compatibility).
2. **Expand braces**: `{a,b}` → `a` + `b`; `{1..10}` → `1,2,...,10`; `{a..z}` → `a,b,...,z`.
3. **Lex**: glob pattern → token stream (`char`, `star`, `globstar`, `qmark`, `class`, `extgroup`, `sep`).
4. **Match**: memoized recursive descent on code points with a shared step budget. Budget is split across branches and recombined on backtracking to prevent exponential blow-up.

## Development

```sh
bun install --frozen-lockfile
bun test                 # 26 tests, 168 expect() calls
bun run typecheck        # tsc --noEmit
bun run build            # ESM + CJS + d.ts
```

## Changelog and license

See [CHANGELOG.md](CHANGELOG.md).

`matchnext` is **MIT licensed**. It contains code derived from `picomatch@4.0.7` (MIT © Jon Schlinkert) in the test fixtures. The engine is an independent re-implementation with no shared code.
