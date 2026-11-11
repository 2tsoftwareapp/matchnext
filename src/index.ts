/**
 * matchnext — ReDoS-hardened glob matcher (picomatch-compatible rewrite).
 *
 * Zero-RegExp engine: pattern → token stream → chart parse + backtracking
 * matcher over code points. No dynamic regex compilation, so pathological
 * patterns cannot trigger regex-engine backtracking blowups (the class of
 * bugs behind CVE-2026-112366 and friends in upstream picomatch).
 */

export interface MatchOptions {
  /** Allow patterns to match paths starting with `.` (default: false) */
  dot?: boolean;
  /** Treat path separators as null bytes (picomatch `splitCharacter`) */
  separator?: string;
  /** Disable extglob parsing `+(…)`, `*(…)`, `?(…)`, `@(…)`, `!(…)` */
  noExtglob?: boolean;
  /** Disable brace expansion `{a,b}` / `{1..3}` */
  noBraces?: boolean;
  /** Case-insensitive matching */
  nocase?: boolean;
}

const DEFAULT_SEPARATOR = "/";

/* ---------------------------------- lexer --------------------------------- */

type TokenKind =
  | "char"      // literal char
  | "star"      // *
  | "globstar"  // **
  | "qmark"     // ?
  | "class"     // [...] — set of allowed chars
  | "ext"       // extglob group with quantifier
  | "sep"       // path separator

interface ClassMember {
  kind: "char" | "range" | "class"; // "class" = POSIX [:alpha:]
  from?: number;
  to?: number;
  posix?: string;
}

interface ClassToken {
  kind: "class";
  negated: boolean;
  members: ClassMember[];
}

interface ExtToken {
  kind: "ext";
  quant: "+" | "*" | "?" | "@" | "!";
  alts: Token[][]; // alternation branches, each a token sequence
}

type Token =
  | { kind: "char"; cp: number }
  | { kind: "star" }
  | { kind: "globstar" }
  | { kind: "qmark" }
  | ClassToken
  | ExtToken
  | { kind: "sep" };

/* --------------------------------- helpers -------------------------------- */

function isSeparator(cp: number, separator: string): boolean {
  return separator.length === 1 ? cp === separator.charCodeAt(0) : false;
}

class PatternError extends Error {}

function assertPattern(pattern: unknown): asserts pattern is string {
  if (typeof pattern !== "string" || pattern.length === 0) {
    throw new TypeError("Expected pattern to be a non-empty string");
  }
}

/* ---------------------------- brace expansion ----------------------------- */

/**
 * Expand `{a,b}` alternations and `{1..3}` / `{a..e}` ranges into multiple
 * patterns. Handles nesting. Returns input untouched when unbalanced.
 * Pure string surgery — no regex.
 */
export function expandBraces(pattern: string, opts: MatchOptions): string[] {
  if (opts.noBraces) return [pattern];

  // find first unescaped '{'
  let open = -1;
  let depth = 0;
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\") { i++; continue; }
    if (inClass) {
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") { inClass = true; continue; }
    if (ch === "{") {
      if (depth === 0) open = i;
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0 && open >= 0) {
        const inner = pattern.slice(open + 1, i);
        const parts = splitTopLevel(inner);
        // numeric or alpha range {1..3} {a..e} {1..3..2}
        if (parts.length === 1) {
          const range = parseRange(parts[0]);
          if (range) {
            const [start, end, step] = range;
            const out: string[] = [];
            if (typeof start === "number" && typeof end === "number") {
              for (let v = start; step > 0 ? v <= end : v >= end; v += step) out.push(String(v));
            } else {
              const sa = start as string;
              const ea = end as string;
              for (let c = sa.charCodeAt(0); c <= ea.charCodeAt(0); c += step) {
                out.push(String.fromCharCode(c));
              }
            }
            return out.flatMap((v) =>
              expandBraces(pattern.slice(0, open) + v + pattern.slice(i + 1), opts),
            );
          }
        }
        if (parts.length > 1) {
          return parts.flatMap((p) =>
            expandBraces(pattern.slice(0, open) + p + pattern.slice(i + 1), opts),
          );
        }
        // single part, not a range: keep literal braces, look for next group
      }
    }
  }
  return [pattern];
}

/** Split on top-level commas (respecting nesting, classes, escapes). */
function splitTopLevel(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  let inClass = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === "\\") { cur += ch + (s[i + 1] ?? ""); i++; continue; }
    if (inClass) {
      cur += ch;
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") { inClass = true; cur += ch; continue; }
    if (ch === "{") depth++;
    if (ch === "}") depth--;
    if (ch === "," && depth === 0) { parts.push(cur); cur = ""; continue; }
    cur += ch;
  }
  parts.push(cur);
  return parts;
}

/** Parse `{1..3}`, `{a..e}`, `{1..10..2}`; null when not a range. */
function parseRange(s: string): [number | string, number | string, number] | null {
  const parts = s.split("..");
  if (parts.length < 2 || parts.length > 3) return null;
  const step = parts.length === 3 ? Number(parts[2]) : 1;
  if (!Number.isFinite(step) || step === 0) return null;
  const a = parts[0];
  const b = parts[1];
  const na = Number(a);
  const nb = Number(b);
  if (Number.isInteger(na) && a.trim() !== "" && Number.isInteger(nb) && b.trim() !== "") {
    const dir = na <= nb ? Math.abs(step) : -Math.abs(step);
    return [na, nb, dir];
  }
  if (a.length === 1 && b.length === 1 && isNaN(na) && isNaN(nb)) {
    return [a, b, Math.abs(step)];
  }
  return null;
}

/* ---------------------------------- lexer --------------------------------- */

const POSIX_CLASSES: Record<string, (cp: number) => boolean> = {
  alpha: (c) => (c >= 97 && c <= 122) || (c >= 65 && c <= 90),
  digit: (c) => c >= 48 && c <= 57,
  alnum: (c) => POSIX_CLASSES.alpha(c) || POSIX_CLASSES.digit(c),
  upper: (c) => c >= 65 && c <= 90,
  lower: (c) => c >= 97 && c <= 122,
  space: (c) => c === 32 || (c >= 9 && c <= 13),
  punct: (c) => c > 32 && c < 127 && !POSIX_CLASSES.alnum(c),
  xdigit: (c) => POSIX_CLASSES.digit(c) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70),
  word: (c) => POSIX_CLASSES.alnum(c) || c === 95,
  blank: (c) => c === 32 || c === 9,
  print: (c) => c >= 32 && c < 127,
  graph: (c) => c > 32 && c < 127,
  cntrl: (c) => c < 32 || c === 127,
};

function lex(pattern: string, opts: MatchOptions): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  const n = pattern.length;
  const separator = opts.separator ?? DEFAULT_SEPARATOR;

  while (i < n) {
    const ch = pattern[i]!;

    if (ch === "\\") {
      // escape: next char is literal
      if (i + 1 < n) {
        tokens.push({ kind: "char", cp: pattern.charCodeAt(i + 1) });
        i += 2;
        continue;
      }
      tokens.push({ kind: "char", cp: 92 });
      i++;
      continue;
    }

    if (isSeparator(ch.charCodeAt(0), separator)) {
      tokens.push({ kind: "sep" });
      i++;
      continue;
    }

    if (ch === "*") {
      if (pattern[i + 1] === "*" && (i + 2 >= n || pattern[i + 2] !== "*")) {
        // `**` — collapse runs of stars >2 not handled: picomatch treats *** as ** + *
        let j = i;
        let stars = 0;
        while (pattern[j] === "*") { stars++; j++; }
        if (stars >= 2) {
          tokens.push({ kind: "globstar" });
          i = j;
          continue;
        }
      }
      tokens.push({ kind: "star" });
      i++;
      continue;
    }

    if (ch === "?") {
      tokens.push({ kind: "qmark" });
      i++;
      continue;
    }

    if (ch === "[") {
      const cls = lexClass(pattern, i);
      if (cls) {
        tokens.push(cls.token);
        i = cls.next;
        continue;
      }
      tokens.push({ kind: "char", cp: 91 });
      i++;
      continue;
    }

    // extglob: (, *(, +(, ?(, @(, !(
    if (!opts.noExtglob) {
      const q = ch as "+" | "*" | "?" | "@" | "!";
      if (pattern[i + 1] === "(" && ("+*?@!".includes(ch))) {
        const res = lexExt(pattern, i, opts);
        tokens.push(res.token);
        i = res.next;
        continue;
      }
      if (ch === "(" && pattern[i - 1] !== "\\" && looksLikeExtgroup(pattern, i)) {
        // bare group with alternation — treat as @(…); content starts after '('
        const res = lexExtFromContent(pattern, i + 1, "@", opts);
        tokens.push(res.token);
        i = res.next;
        continue;
      }
    }

    // surrogate pair support
    const cp = pattern.codePointAt(i)!;
    tokens.push({ kind: "char", cp });
    i += cp > 0xffff ? 2 : 1;
  }
  return tokens;
}

/** `[...]` starting at pattern[start] === '['; null when it's a literal '['. */
function lexClass(pattern: string, start: number): { token: ClassToken; next: number } | null {
  let i = start + 1;
  let negated = false;
  const members: ClassMember[] = [];
  let first = true;

  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "]" && !first) {
      return { token: { kind: "class", negated, members }, next: i + 1 };
    }
    first = false;

    if (ch === "!" && members.length === 0 && i === start + 1) {
      negated = true;
      i++;
      continue;
    }

    // POSIX [:alpha:]
    if (ch === "[" && pattern[i + 1] === ":") {
      const end = pattern.indexOf(":]", i + 2);
      if (end !== -1) {
        const name = pattern.slice(i + 2, end);
        if (name in POSIX_CLASSES) {
          members.push({ kind: "class", posix: name });
          i = end + 2;
          continue;
        }
      }
    }

    let cp: number;
    if (ch === "\\") {
      if (i + 1 >= pattern.length) cp = 92;
      else cp = pattern.charCodeAt(i + 1);
      i += 2;
    } else {
      cp = pattern.codePointAt(i)!;
      i += cp > 0xffff ? 2 : 1;
    }

    // range a-z (dash not last)
    if (pattern[i] === "-" && pattern[i + 1] && pattern[i + 1] !== "]") {
      let hi: number;
      let j = i + 1;
      if (pattern[j] === "\\") {
        hi = pattern.charCodeAt(j + 1) ?? 92;
        j += 2;
      } else {
        hi = pattern.codePointAt(j)!;
        j += hi > 0xffff ? 2 : 1;
      }
      members.push({ kind: "range", from: cp, to: hi });
      i = j;
      continue;
    }

    members.push({ kind: "char", from: cp });
  }
  return null; // unbalanced — treat '[' as literal
}

/** Does a '(' at start begin an alternation group? (a|b) */
function looksLikeExtgroup(pattern: string, open: number): boolean {
  let depth = 1;
  let i = open + 1;
  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "\\") { i += 2; continue; }
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) {
        // must contain top-level '|' and nothing after? keep simple: contains '|'
        return pattern.slice(open + 1, i).includes("|");
      }
    }
    i++;
  }
  return false;
}

function lexExt(
  pattern: string,
  start: number,
  opts: MatchOptions,
): { token: ExtToken; next: number } {
  const quant = pattern[start] as ExtToken["quant"];
  // start points at the quantifier char; content starts after '(' at start+2
  return lexExtFromContent(pattern, start + 2, quant, opts);
}

function lexExtFromContent(
  pattern: string,
  contentStart: number,
  quant: ExtToken["quant"],
  opts: MatchOptions,
): { token: ExtToken; next: number } {
  // scan to matching close paren
  let depth = 1;
  let i = contentStart;
  let inClass = false;
  while (i < pattern.length) {
    const ch = pattern[i]!;
    if (ch === "\\") { i += 2; continue; }
    if (inClass) {
      if (ch === "]") inClass = false;
      i++;
      continue;
    }
    if (ch === "[") inClass = true;
    else if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) break;
    }
    i++;
  }
  const content = pattern.slice(contentStart, i);
  // split alternation on top-level '|'
  const branches = splitAlternation(content);
  const alts = branches.map((b) => lex(b, opts));
  return { token: { kind: "ext", quant, alts }, next: i + 1 };
}

function splitAlternation(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  let inClass = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (ch === "\\") { cur += ch + (s[i + 1] ?? ""); i++; continue; }
    if (inClass) {
      cur += ch;
      if (ch === "]") inClass = false;
      continue;
    }
    if (ch === "[") { inClass = true; cur += ch; continue; }
    if (ch === "(") depth++;
    if (ch === ")") depth--;
    if (ch === "|" && depth === 0) { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  out.push(cur);
  return out;
}

/* --------------------------------- matcher -------------------------------- */

/** Matching state after consuming tokens vs input positions. */
interface MatchState {
  matched: boolean;
}

class Matcher {
  private memo = new Map<string, boolean>();
  private steps = 0;
  private readonly maxSteps: number;
  constructor(
    private readonly input: number[],
    private readonly opts: Required<Pick<MatchOptions, "dot">>,
    private readonly separator: string,
    private readonly nocase: boolean,
  ) {
    // O(len(pattern) × len(input)) cap; generous but polynomial — this is the
    // ReDoS guard. Upstream picomatch blows up exponentially on some inputs.
    this.maxSteps = 4_000_000 + 400 * input.length * 40;
  }

  /** Budget-sharing hook for sub-matchers (sequenceMatch). */
  adoptBudgetOf(parent: Matcher): void {
    (this as unknown as { maxSteps: number }).maxSteps = parent.maxSteps;
  }

  private norm(cp: number): number {
    return this.nocase ? cp | 0x20 : cp;
  }

  private classMatch(cls: ClassToken, cp: number): boolean {
    let hit = false;
    const target = this.norm(cp);
    for (const m of cls.members) {
      let ok = false;
      if (m.kind === "char") ok = this.norm(m.from!) === target;
      else if (m.kind === "range") ok = target >= this.norm(m.from!) && target <= this.norm(m.to!);
      else if (m.kind === "class") ok = POSIX_CLASSES[m.posix!]!(cp);
      if (ok) { hit = true; break; }
    }
    return cls.negated ? !hit : hit;
  }

  private canStartSegment(pos: number): boolean {
    // dotfile rule: pattern wildcards at segment start cannot match '.' unless dot:true
    if (this.opts.dot) return true;
    return !(this.input[pos] === 0x2e /* . */);
  }

  /** match token sequence tokens[ti..] against input[ip..] */
  match(tokens: Token[], ti: number, ip: number): boolean {
    this.steps++;
    if (this.steps > this.maxSteps) throw new Error("matchnext: pattern complexity limit exceeded");

    const key = `${ti}:${ip}`;
    if (this.memo.has(key)) return this.memo.get(key)!;

    const result = this.matchInner(tokens, ti, ip);
    this.memo.set(key, result);
    return result;
  }

  private matchInner(tokens: Token[], ti: number, ip: number): boolean {
    while (true) {
      if (ti >= tokens.length) return ip >= this.input.length;

      const tok = tokens[ti]!;

      switch (tok.kind) {
        case "char": {
          if (ip >= this.input.length) return false;
          if (this.norm(tok.cp) !== this.norm(this.input[ip]!)) return false;
          ti++; ip++;
          continue;
        }
        case "sep": {
          if (ip >= this.input.length) return false;
          if (!isSeparator(this.input[ip]!, this.separator)) return false;
          ti++; ip++;
          continue;
        }
        case "qmark": {
          if (ip >= this.input.length) return false;
          if (isSeparator(this.input[ip]!, this.separator)) return false;
          if (!this.canStartSegment(ip) && this.atSegmentStart(tokens, ti)) return false;
          ti++; ip++;
          continue;
        }
        case "star": {
          // try longest-first is unnecessary; memoized DFS over end positions
          // star cannot cross separator; dot rule at segment start
          const startsSegment = this.atSegmentStart(tokens, ti);
          for (let end = ip; end <= this.input.length; end++) {
            // segment boundary check for [ip..end)
            if (this.spansSeparator(ip, end)) break;
            if (startsSegment && !this.canStartSegment(ip) && ip < end) break;
            if (this.match(tokens, ti + 1, end)) return true;
            if (startsSegment && !this.canStartSegment(ip) && end === ip) {
              // even zero-length is fine only if dot allowed... zero-length star
              // matches empty; allowed regardless (matches nothing)
            }
          }
          return false;
        }
        case "globstar": {
          // ** matches zero or more path segments
          // zero-segment case: **/ → skip the following sep token too
          if (tokens[ti + 1]?.kind === "sep") {
            if (this.match(tokens, ti + 2, ip)) return true;
          } else {
            if (this.match(tokens, ti + 1, ip)) return true;
          }
          // one-or-more segments
          for (let end = ip; end <= this.input.length; end++) {
            if (end > ip && isSeparator(this.input[end - 1]!, this.separator)) {
              if (this.match(tokens, ti, end)) return true;
              // also allow ** to consume up to (not incl.) separator
            }
          }
          // also: ** at end matches everything remaining
          if (ti + 1 >= tokens.length) return true;
          return false;
        }
        case "class": {
          if (ip >= this.input.length) return false;
          if (isSeparator(this.input[ip]!, this.separator)) return false;
          if (this.atSegmentStart(tokens, ti) && !this.canStartSegment(ip)) return false;
          if (!this.classMatch(tok, this.input[ip]!)) return false;
          ti++; ip++;
          continue;
        }
        case "ext": {
          return this.matchExt(tok, tokens, ti, ip);
        }
      }
    }
  }

  /** Is token index ti positioned at the start of a path segment? */
  private atSegmentStart(tokens: Token[], ti: number): boolean {
    return ti === 0 || tokens[ti - 1]?.kind === "sep" || tokens[ti - 1]?.kind === "globstar";
    // note: after globstar there's usually a sep; conservative
  }

  private spansSeparator(from: number, to: number): boolean {
    for (let i = from; i < to; i++) {
      if (isSeparator(this.input[i]!, this.separator)) return true;
    }
    return false;
  }

  /** Does branch token-sequence match exactly input[ip..end)? Runs on a
   *  throwaway sub-matcher so it cannot pollute the parent memo. */
  private sequenceMatch(branch: Token[], ip: number, end: number): boolean {
    const sub = new Matcher(
      this.input.slice(ip, end),
      this.opts,
      this.separator,
      this.nocase,
    );
    sub.steps = this.steps;
    sub.adoptBudgetOf(this);
    const ok = sub.match(branch, 0, 0);
    this.steps = sub.steps;
    return ok;
  }

  /** Match extglob token at tokens[ti] with continuation tokens[ti+1..]. */
  private matchExt(tok: ExtToken, tokens: Token[], ti: number, ip: number): boolean {
    const restTi = ti + 1; // continuation index within the SAME array
    switch (tok.quant) {
      case "@":
      case "?": {
        // exactly one branch (? also allows zero occurrences)
        for (let end = ip; end <= this.input.length; end++) {
          for (const branch of tok.alts) {
            if (this.sequenceMatch(branch, ip, end) && this.match(tokens, restTi, end)) {
              return true;
            }
          }
        }
        // zero occurrences allowed only for ?
        return tok.quant === "?" && this.match(tokens, restTi, ip);
      }
      case "+":
      case "*": {
        return this.matchRepeat(tok, tokens, restTi, ip, tok.quant === "+" ? 1 : 0);
      }
      case "!": {
        // picomatch compiles !(X) to: (?=.)  (?!(X)$ or X-prefix)  [^/]*?  REST
        // At pattern end the lookahead is anchored: match any single-segment,
        // non-empty remainder that is not exactly X.
        if (restTi >= tokens.length) {
          if (ip >= this.input.length) return false; // (?=.)
          if (this.spansSeparator(ip, this.input.length)) return false;
          for (const branch of tok.alts) {
            if (this.sequenceMatch(branch, ip, this.input.length)) return false;
          }
          return true;
        }
        // Not at end: X must not prefix-match at ip, then lazy [^/]*? then REST
        for (const branch of tok.alts) {
          for (let end = ip; end <= this.input.length; end++) {
            if (this.sequenceMatch(branch, ip, end)) return false;
          }
        }
        for (let k = ip; k <= this.input.length; k++) {
          if (k > ip && isSeparator(this.input[k - 1]!, this.separator)) break;
          if (this.match(tokens, restTi, k)) return true;
        }
        return false;
      }
      default:
        return false;
    }
  }

  /** Repetition matching for +(…) and *(…): DFS over (position, min-satisfied)
   *  with memoization — the polynomial guarantee that keeps CVE-2026-112366
   *  style patterns fast. */
  private matchRepeat(
    tok: ExtToken,
    tokens: Token[],
    restTi: number,
    ip: number,
    min: number,
  ): boolean {
    const repMemo = new Map<string, boolean>();
    const repeat = (pos: number, satisfied: boolean): boolean => {
      const key = `${pos}:${satisfied ? 1 : 0}`;
      const cached = repMemo.get(key);
      if (cached !== undefined) return cached;

      let result = false;
      if (satisfied && this.match(tokens, restTi, pos)) {
        result = true;
      } else {
        outer: for (const branch of tok.alts) {
          for (let end = pos + 1; end <= this.input.length; end++) {
            if (this.sequenceMatch(branch, pos, end) && repeat(end, true)) {
              result = true;
              break outer;
            }
          }
          // empty-matching branch can satisfy min without consuming input
          if (!satisfied && this.sequenceMatch(branch, pos, pos) && repeat(pos, true)) {
            result = true;
            break;
          }
        }
      }
      repMemo.set(key, result);
      return result;
    };
    return repeat(ip, min === 0);
  }
}

/* ---------------------------------- API ----------------------------------- */

export function isMatch(input: string, patterns: string | string[], options?: MatchOptions): boolean {
  if (typeof patterns === "string") patterns = [patterns];
  if (!Array.isArray(patterns)) {
    throw new TypeError("Expected pattern to be a non-empty string");
  }
  for (const p of patterns) {
    assertPattern(p);
    const expanded = expandBraces(p, options ?? {});
    for (const ex of expanded) {
      const tokens = lex(ex, options ?? {});
      const cps = Array.from(input).map((c) => c.codePointAt(0)!);
      const m = new Matcher(cps, { dot: options?.dot ?? false }, options?.separator ?? DEFAULT_SEPARATOR, options?.nocase ?? false);
      if (m.match(tokens, 0, 0)) return true;
    }
  }
  return false;
}

export function match(
  list: string[],
  patterns: string | string[],
  options?: MatchOptions,
): string[] {
  return list.filter((item) => isMatch(item, patterns, options));
}
