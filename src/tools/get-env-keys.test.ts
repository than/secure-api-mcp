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

    expect(await getEnvKeys({ project_dir: "/fake/project" })).toEqual({
      keys: ["PRIVATE_KEY"],
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
