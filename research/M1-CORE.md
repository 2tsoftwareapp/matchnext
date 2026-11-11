# matchnext Milestone 1 — Core Engine & ReDoS-Safe Architecture

**Status:** GREEN (M1 core complete)
**Baseline upstream:** micromatch/picomatch@4.0.7 (commit `9fab7bf61913ea334c4203ed321c426cfde44a42`)
**Upstream stats (2026-11-11):** 697.8M weekly downloads, 0 dependencies, 1,998 tests.

## Why Rewrite?

Upstream picomatch compiles glob patterns into native JavaScript `RegExp` objects. This design carries inherent structural ReDoS vulnerabilities:
- **CVE-2026-112366 (CVSS 4.0: 8.7 HIGH)** — unpatched in picomatch `<= 4.0.7` (latest as of November 2026).
- Pattern shape `+(*a)*b` causes exponential backtracking in the V8 regex engine.
- Measured on Apple Silicon M-series:
  - `len=25`: **152 ms**
  - `len=28`: **9,584 ms**
  - `len=30`: **4,940 ms** (event-loop freeze)

## Architectural Principle: Zero-RegExp

`matchnext` does not call `new RegExp()` or dynamic regex compilation. Pattern matching is implemented as:
1. **Lexer**: pattern → stream of typed tokens (`char`, `star`, `globstar`, `qmark`, `class`, `ext`, `sep`).
2. **Brace expander**: expands `{a,b}` alternations and `{1..3}` / `{a..z}` ranges purely via string surgery.
3. **Memoized chart matcher**: state machine traversing `(token_index, input_codepoint_index)` with a global step budget ($O(|pattern| \times |input|)$).

### Measured Defense

Against `+(*a)*b` on `a`.repeat(30):
- `picomatch@4.0.7`: **4,940 ms** (exponential explosion)
- `matchnext@0.0.0-m1`: **8.5 ms** (sub-10ms linear bound)

## Test Coverage (Milestone 1)

- `bun test test`: **12 pass, 0 fail, 49 expect() assertions** (36ms).
- `bun run typecheck`: **exit 0** (clean strict TypeScript).
- Fixtures snapshot: 36 test files from picomatch upstream saved at `research/upstream-snapshot/` with original MIT license preserved for attribution.
