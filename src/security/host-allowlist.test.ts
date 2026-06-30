import { describe, it, expect } from "vitest";
import { getHostPolicy } from "./host-allowlist.js";

describe("getHostPolicy - unenforced (no allowlist)", () => {
  it("is not enforced and allows everything when var is unset", () => {
    const policy = getHostPolicy({} as NodeJS.ProcessEnv);
    expect(policy.enforced).toBe(false);
    expect(policy.allows("anything.example.com")).toBe(true);
  });

  it("is not enforced when var is empty or whitespace", () => {
    expect(getHostPolicy({ SECURE_API_ALLOWED_HOSTS: "" } as NodeJS.ProcessEnv).enforced).toBe(false);
    expect(getHostPolicy({ SECURE_API_ALLOWED_HOSTS: "  ,  " } as NodeJS.ProcessEnv).enforced).toBe(false);
  });
});

describe("getHostPolicy - enforced (allowlist set)", () => {
  it("allows exact host matches and blocks others", () => {
    const policy = getHostPolicy({
      SECURE_API_ALLOWED_HOSTS: "api.stripe.com, api.github.com",
    } as NodeJS.ProcessEnv);
    expect(policy.enforced).toBe(true);
    expect(policy.allows("api.stripe.com")).toBe(true);
    expect(policy.allows("api.github.com")).toBe(true);
    expect(policy.allows("evil.example.com")).toBe(false);
  });

  it("matches case-insensitively", () => {
    const policy = getHostPolicy({
      SECURE_API_ALLOWED_HOSTS: "Api.Stripe.Com",
    } as NodeJS.ProcessEnv);
    expect(policy.allows("api.stripe.com")).toBe(true);
  });

  it("supports leading-wildcard subdomain matches, including the apex", () => {
    const policy = getHostPolicy({
      SECURE_API_ALLOWED_HOSTS: "*.example.com",
    } as NodeJS.ProcessEnv);
    expect(policy.allows("a.example.com")).toBe(true);
    expect(policy.allows("a.b.example.com")).toBe(true);
    expect(policy.allows("example.com")).toBe(true);
    expect(policy.allows("notexample.com")).toBe(false);
    expect(policy.allows("example.com.evil.com")).toBe(false);
  });

  it("strips brackets from IPv6 literal hosts before matching", () => {
    const policy = getHostPolicy({
      SECURE_API_ALLOWED_HOSTS: "::1",
    } as NodeJS.ProcessEnv);
    expect(policy.allows("[::1]")).toBe(true);
  });
});
