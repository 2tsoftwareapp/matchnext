import { describe, test, expect } from "bun:test";
import { isMatch, match } from "../src/index.ts";

describe("matchnext M1 core", () => {
  test("isMatch handles plain literals", () => {
    expect(isMatch("foo", "foo")).toBe(true);
    expect(isMatch("foo", "bar")).toBe(false);
    expect(isMatch("a/b/c", "a/b/c")).toBe(true);
  });

  test("isMatch throws on empty pattern", () => {
    expect(() => isMatch("foo", "")).toThrow(/non-empty string/);
    expect(() => isMatch("foo", null as unknown as string)).toThrow(/non-empty string/);
  });

  test("? matches exactly one non-separator char", () => {
    expect(isMatch("ab", "a?")).toBe(true);
    expect(isMatch("a", "a?")).toBe(false);
    expect(isMatch("a/b", "a?")).toBe(false);
    expect(isMatch("a/b", "?/?")).toBe(true);
  });

  test("* matches zero or more non-separator chars", () => {
    expect(isMatch("ab", "*")).toBe(true);
    expect(isMatch("a/b", "*")).toBe(false);
    expect(isMatch("ab", "*b")).toBe(true);
    expect(isMatch("ab", "a*")).toBe(true);
    expect(isMatch("", "*")).toBe(true);
  });

  test("** (globstar) spans separators", () => {
    expect(isMatch("a/b/c", "**")).toBe(true);
    expect(isMatch("a/b/c", "a/**")).toBe(true);
    expect(isMatch("a/b/c", "**/c")).toBe(true);
    expect(isMatch("a/b/c", "a/**/c")).toBe(true);
    expect(isMatch("a/b/c/d", "a/**/d")).toBe(true);
    expect(isMatch("a/b/c", "**/*.md")).toBe(false);
    expect(isMatch("a/b/c.md", "**/*.md")).toBe(true);
  });

  test("multiple patterns return true if any match", () => {
    expect(isMatch("ab", ["*", "foo", "bar"])).toBe(true);
    expect(isMatch("a/b/c", ["a/b", "foo"])).toBe(false);
  });

  test("character classes: ranges, negation, specials", () => {
    expect(isMatch("a", "[a-z]")).toBe(true);
    expect(isMatch("A", "[a-z]")).toBe(false);
    expect(isMatch("a", "[!a-z]")).toBe(false);
    expect(isMatch("b", "[!a]")).toBe(true);
    expect(isMatch("]", "[]]")).toBe(true);
    expect(isMatch("a-b", "[a-]")).toBe(false);
  });

  test("braces expand", () => {
    expect(isMatch("a", "{a,b}")).toBe(true);
    expect(isMatch("b", "{a,b}")).toBe(true);
    expect(isMatch("c", "{a,b}")).toBe(false);
    expect(isMatch("a/c", "{a,b}/c")).toBe(true);
    expect(isMatch("ab", "a{b,c}d")).toBe(false);
  });

  test("extglob basics", () => {
    expect(isMatch("a", "+(a)")).toBe(true);
    expect(isMatch("aa", "+(a)")).toBe(true);
    expect(isMatch("b", "+(a)")).toBe(false);
    expect(isMatch("abc", "+(ab)*")).toBe(true);
    expect(isMatch("ab", "!(a)")).toBe(true);
    expect(isMatch("a", "!(a)")).toBe(false);
  });

  test("dot files are not matched by wildcards by default", () => {
    expect(isMatch(".a", "*")).toBe(false);
    expect(isMatch(".a", ".*")).toBe(true);
    expect(isMatch(".c.md", ".*.md")).toBe(true);
    expect(isMatch(".c.md", "*.md")).toBe(false);
    expect(isMatch("c.md", "*.md")).toBe(true);
  });

  test("match() returns matched items", () => {
    expect(match(["foo", "bar", "baz"], "*a*")).toEqual(["bar", "baz"]);
    expect(match(["foo", "bar"], "foo")).toEqual(["foo"]);
  });

  test("ReDoS guard: CVE-2026-112366 pattern stays fast", () => {
    const input = "a".repeat(30);
    const t0 = performance.now();
    const result = isMatch(input, "+(*a)*b");
    const elapsed = performance.now() - t0;
    expect(result).toBe(false);
    // upstream picomatch@4.0.7 takes seconds on this input; we require <100ms
    expect(elapsed).toBeLessThan(100);
  });
});
