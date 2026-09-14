import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../env-loader.js");
vi.mock("../security/audit.js");
vi.mock("../security/path-validator.js");

const { loadEnvChecked } = await import("../env-loader.js");
const { getEnvKeys } = await import("./get-env-keys.js");
const { validateProjectDir } = await import("../security/path-validator.js");
const mockLoadEnvChecked = vi.mocked(loadEnvChecked);
const mockValidateProjectDir = vi.mocked(validateProjectDir);

describe("getEnvKeys", () => {
  beforeEach(() => {
    mockLoadEnvChecked.mockReset();
    mockValidateProjectDir.mockReturnValue({ valid: true });
  });

  it("returns the keys present in .env", async () => {
    mockLoadEnvChecked.mockReturnValue({ env: { API_KEY: "x", PORT: "3000" } });

    expect(await getEnvKeys({ project_dir: "/fake/project" })).toEqual({
      keys: ["API_KEY", "PORT"],
    });
  });

  it("does not return a value fragment as a key name", async () => {
    // dotenv turns the lines of an unquoted multi-line value into keys, so a
    // base64 chunk of a private key can arrive here as a key *name*.
    mockLoadEnvChecked.mockReturnValue({
      env: {
        PRIVATE_KEY: "-----BEGIN RSA PRIVATE KEY-----",
        QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5: "",
      },
    });

    const result = await getEnvKeys({ project_dir: "/fake/project" });

    expect(result).toMatchObject({ keys: ["PRIVATE_KEY"] });
    // Dropping it silently would read as a missing variable.
    const warning = (result as { warnings?: string[] }).warnings?.join(" ") ?? "";
    expect(warning).toMatch(/Omitted 1 key/);
    // No bytes of the omitted key: even a truncated stub is a slice of a value.
    expect(warning).not.toContain("QUJDREVG");
    expect(warning).toMatch(/env_keys/);
  });

  it("keeps a dotted key that is not a fragment", async () => {
    // Lowercase and dotted: a real Spring-style key, no mixed case.
    mockLoadEnvChecked.mockReturnValue({
      env: { "spring.datasource.password": "x" },
    });

    expect(await getEnvKeys({ project_dir: "/fake/project" })).toEqual({
      keys: ["spring.datasource.password"],
    });
  });

  it("surfaces a policy refusal rather than an empty list", async () => {
    mockLoadEnvChecked.mockReturnValue({ env: {}, blocked: "symlink refused" });

    expect(await getEnvKeys({ project_dir: "/fake/project" })).toEqual({
      keys: [],
      warnings: ["symlink refused"],
    });
  });
});
