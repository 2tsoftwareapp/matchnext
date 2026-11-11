import { describe, test, expect } from "bun:test";
import { isMatch, match } from "../src/index.ts";

describe("matchnext baseline vs upstream picomatch fixtures", () => {
  // api.picomatch.js
  describe("multiple patterns", () => {
    test("should return true when any of the patterns match", () => {
      expect(isMatch(".", [".", "foo"])).toBe(true);
      expect(isMatch("a", ["a", "foo"])).toBe(true);
      expect(isMatch("ab", ["*", "foo", "bar"])).toBe(true);
      expect(isMatch("ab", ["*b", "foo", "bar"])).toBe(true);
      expect(isMatch("ab", ["./*", "foo", "bar"])).toBe(true);
      expect(isMatch("ab", ["a*", "foo", "bar"])).toBe(true);
      expect(isMatch("ab", ["ab", "foo"])).toBe(true);
    });

    test("should return false when none of the patterns match", () => {
      expect(isMatch("/ab", ["/a", "foo"])).toBe(false);
      expect(isMatch("/ab", ["?/?", "foo", "bar"])).toBe(false);
      expect(isMatch("/ab", ["a/*", "foo", "bar"])).toBe(false);
      expect(isMatch("a/b/c", ["a/b", "foo"])).toBe(false);
      expect(isMatch("ab", ["*/*", "foo", "bar"])).toBe(false);
      expect(isMatch("ab", ["/a", "foo", "bar"])).toBe(false);
      expect(isMatch("ab", ["a", "foo"])).toBe(false);
      expect(isMatch("ab", ["b", "foo"])).toBe(false);
      expect(isMatch("ab", ["c", "foo", "bar"])).toBe(false);
      expect(isMatch("abcd", ["ab", "foo"])).toBe(false);
      expect(isMatch("abcd", ["bc", "foo"])).toBe(false);
      expect(isMatch("abcd", ["c", "foo"])).toBe(false);
      expect(isMatch("abcd", ["cd", "foo"])).toBe(false);
      expect(isMatch("abcd", ["d", "foo"])).toBe(false);
      expect(isMatch("abcd", ["f", "foo", "bar"])).toBe(false);
      expect(isMatch("ef", ["/*", "foo", "bar"])).toBe(false);
    });
  });

  describe("file extensions", () => {
    test("should match files that contain the given extension", () => {
      expect(isMatch(".c.md", "*.md")).toBe(false);
      expect(isMatch(".c.md", ".c.")).toBe(false);
      expect(isMatch(".c.md", ".md")).toBe(false);
      expect(isMatch(".md", "*.md")).toBe(false);
      expect(isMatch(".md", ".m")).toBe(false);
      expect(isMatch("a/b/c.md", "*.md")).toBe(false);
      expect(isMatch("a/b/c.md", ".md")).toBe(false);
      expect(isMatch("a/b/c.md", "a/*.md")).toBe(false);
      expect(isMatch("a/b/c/c.md", "*.md")).toBe(false);
      expect(isMatch("a/b/c/c.md", "c.js")).toBe(false);
      expect(isMatch(".c.md", ".*.md")).toBe(true);
      expect(isMatch(".md", ".md")).toBe(true);
      expect(isMatch("a/b/c.js", "a/**/*.*")).toBe(true);
      expect(isMatch("a/b/c.md", "**/*.md")).toBe(true);
      expect(isMatch("a/b/c.md", "a/*/*.md")).toBe(true);
      expect(isMatch("c.md", "*.md")).toBe(true);
    });
  });

  describe("dot files", () => {
    test("should not match dotfiles when a leading dot is not defined in a path segment", () => {
      expect(isMatch(".a", "(a)*")).toBe(false);
      expect(isMatch(".a", "*(a|b)")).toBe(false);
      expect(isMatch(".a", "*.md")).toBe(false);
      expect(isMatch(".a", "*[a]")).toBe(false);
      expect(isMatch(".a", "*[a]*")).toBe(false);
      expect(isMatch(".a", "*a")).toBe(false);
      expect(isMatch(".a", "*a*")).toBe(false);
      expect(isMatch(".a.md", "a/b/c/*.md")).toBe(false);
      expect(isMatch(".ab", "*.*")).toBe(false);
      expect(isMatch(".abc", ".a")).toBe(false);
      expect(isMatch(".ba", ".a")).toBe(false);
      expect(isMatch(".c.md", "*.md")).toBe(false);
      expect(isMatch(".md", "a/b/c/*.md")).toBe(false);
      expect(isMatch(".txt", ".md")).toBe(false);
      expect(isMatch(".verb.txt", "*.md")).toBe(false);
      expect(isMatch("a/.c.md", "*.md")).toBe(false);
      expect(isMatch("a/b/d/.md", "a/b/c/*.md")).toBe(false);
      expect(isMatch(".a", ".a")).toBe(true);
      expect(isMatch(".ab", ".*")).toBe(true);
      expect(isMatch(".ab", ".a*")).toBe(true);
      expect(isMatch(".b", ".b*")).toBe(true);
      expect(isMatch(".md", ".md")).toBe(true);
      expect(isMatch("a/.c.md", "a/.c.md")).toBe(true);
      expect(isMatch("a/b/c/.xyz.md", "a/b/c/.*.md")).toBe(true);
      expect(isMatch("a/b/c/d.a.md", "a/b/c/*.md")).toBe(true);
    });

    test("should match dotfiles when options.dot is true", () => {
      expect(isMatch("a/b/c/.xyz.md", ".*.md", { dot: true })).toBe(false);
      expect(isMatch(".c.md", "*.md", { dot: true })).toBe(true);
      expect(isMatch(".c.md", ".*", { dot: true })).toBe(true);
      expect(isMatch("a/b/c/.xyz.md", "**/*.md", { dot: true })).toBe(true);
      expect(isMatch("a/b/c/.xyz.md", "**/.*.md", { dot: true })).toBe(true);
      expect(isMatch("a/b/c/.xyz.md", "a/b/c/*.md", { dot: true })).toBe(true);
      expect(isMatch("a/b/c/.xyz.md", "a/b/c/.*.md", { dot: true })).toBe(true);
    });
  });
});

describe("stars", () => {
  describe("issue related", () => {
    test("should respect dots defined in glob pattern (micromatch/#23)", () => {
      expect(isMatch("z.js", "z*")).toBe(true);
      expect(isMatch("zzjs", "z*.js")).toBe(false);
      expect(isMatch("zzjs", "*z.js")).toBe(false);
    });
  });

  describe("single stars", () => {
    test("should match anything except slashes and leading dots", () => {
      expect(isMatch("a/b/c/z.js", "*.js")).toBe(false);
      expect(isMatch("a/b/z.js", "*.js")).toBe(false);
      expect(isMatch("a/z.js", "*.js")).toBe(false);
      expect(isMatch("z.js", "*.js")).toBe(true);

      expect(isMatch("a/.ab", "*/*")).toBe(false);
      expect(isMatch(".ab", "*")).toBe(false);

      expect(isMatch("z.js", "z*.js")).toBe(true);
      expect(isMatch("a/z", "*/*")).toBe(true);
      expect(isMatch("a/z.js", "*/z*.js")).toBe(true);
      expect(isMatch("a/z.js", "a/z*.js")).toBe(true);

      expect(isMatch("ab", "*")).toBe(true);
    });
  });
});

describe("negation", () => {
  test("!(a) basics", () => {
    expect(isMatch("ab", "!(a)")).toBe(true);
    expect(isMatch("a", "!(a)")).toBe(false);
    expect(isMatch("ab/c", "!(a)")).toBe(false);
    expect(isMatch("", "!(a)")).toBe(false);
    expect(isMatch("b", "!(a)")).toBe(true);
    expect(isMatch("ab", "!(aa)")).toBe(true);
  });

  test("!(a|b) alternation", () => {
    expect(isMatch("c", "!(a|b)")).toBe(true);
    expect(isMatch("a", "!(a|b)")).toBe(false);
    expect(isMatch("ab", "!(a|b)")).toBe(true);
  });

  test("!(a)b continuation", () => {
    expect(isMatch("ab", "!(a)b")).toBe(false);
    expect(isMatch("cb", "!(a)b")).toBe(true);
    expect(isMatch("bb", "!(a)b")).toBe(true);
  });

  test("!(a).js", () => {
    expect(isMatch("ab.js", "!(a)*.js")).toBe(false);
    expect(isMatch("b.js", "!(a)*.js")).toBe(true);
    expect(isMatch("b.js", "!(a).js")).toBe(true);
    expect(isMatch("xb", "x!(a)")).toBe(true);
    expect(isMatch("bx", "!(a)x")).toBe(true);
  });
});

describe("qmarks", () => {
  test("should match exactly one non-separator char", () => {
    expect(isMatch("ab", "a?")).toBe(true);
    expect(isMatch("a", "a?")).toBe(false);
    expect(isMatch("a/b", "a?")).toBe(false);
    expect(isMatch("a/b", "?/?")).toBe(true);
  });
});

describe("globstars", () => {
  test("should match zero or more path segments", () => {
    expect(isMatch("a/b/c", "a/**")).toBe(true);
    expect(isMatch("a/b/c", "**/c")).toBe(true);
    expect(isMatch("a/b/c", "a/**/c")).toBe(true);
    expect(isMatch("a/b/c/d", "a/**/d")).toBe(true);
    expect(isMatch("a/b/c.md", "**/*.md")).toBe(true);
    expect(isMatch("a/b/c/c.md", "*.md")).toBe(false);
  });
});

describe("braces", () => {
  test("should expand alternation", () => {
    expect(isMatch("a", "{a,b}")).toBe(true);
    expect(isMatch("b", "{a,b}")).toBe(true);
    expect(isMatch("c", "{a,b}")).toBe(false);
    expect(isMatch("a/c", "{a,b}/c")).toBe(true);
    expect(isMatch("ab", "a{b,c}d")).toBe(false);
    expect(isMatch("abd", "a{b,c}d")).toBe(true);
    expect(isMatch("acd", "a{b,c}d")).toBe(true);
  });
});
