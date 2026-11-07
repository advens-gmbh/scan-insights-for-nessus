import { describe, expect, it } from "vitest";
import { isWebUrl, metasploitSearchUrl } from "./openExternal";

describe("metasploitSearchUrl", () => {
  it("searches by the module name", () => {
    expect(metasploitSearchUrl("MS08-067 Microsoft Server Service")).toBe(
      "https://www.rapid7.com/db/?q=MS08-067%20Microsoft%20Server%20Service&type=metasploit"
    );
  });

  it("leaves out a trailing nickname, which the search can't match", () => {
    expect(metasploitSearchUrl("Apache Range Header DoS (Apache Killer)")).toBe(
      "https://www.rapid7.com/db/?q=Apache%20Range%20Header%20DoS&type=metasploit"
    );
  });

  it("keeps a name that is only a nickname", () => {
    expect(metasploitSearchUrl("(Killer)")).toContain("q=(Killer)&");
  });

  it.each(["a <= 2.2 b", 'quote " back\\slash', "ünicode ‮", "user@host/x?y#z&q=1"])(
    "always builds a link the app can open: %s",
    (name) => expect(isWebUrl(metasploitSearchUrl(name))).toBe(true)
  );
});

describe("isWebUrl", () => {
  it.each([
    "http://example.com",
    "https://example.com/a?b=c&d=e",
    "HTTPS://EXAMPLE.COM",
    "https://example.com/user@host",
    "https://example.com:8443/a",
  ])("accepts %s", (url) => expect(isWebUrl(url)).toBe(true));

  it.each([
    "",
    "calc.exe",
    "C:\\Windows\\System32\\calc.exe",
    "\\\\attacker\\share\\x.exe",
    "file:///C:/x.exe",
    "javascript:alert(1)",
    "http://",
    "https:///etc/passwd",
    "http:\\\\example.com",
    'http://a" & calc.exe',
    "http://a b",
    "http://user:pass@example.com/",
    "https://bank.example@evil.example/",
    "https://example.com/\u202Emoc.elgoog",
    "https://ex\u0430mple.com/",
  ])("rejects %s", (url) => expect(isWebUrl(url)).toBe(false));
});
