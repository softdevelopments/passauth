/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from "@jest/globals";
import { Passauth } from "../../src";
import { PassauthConfiguration, User } from "../../src/auth/auth.types";
import { PassauthMissingConfigurationException } from "../../src/auth/auth.exceptions";
import { AuthRepo } from "../../src/auth/auth.types";

const repoMock: AuthRepo<User> = {
  getUser: async (_email) => null,
  createUser: async (_params) => {
    return {
      id: 1,
      email: "user@email.com",
      password: "password123",
    };
  },
};

const passauthConfig: PassauthConfiguration<User> = {
  secretKey: "secretKey",
  saltingRounds: 4,
  accessTokenExpirationMs: 1000 * 60,
  refreshTokenExpirationMs: 1000 * 60 * 15,
  repo: repoMock,
};

describe("Passauth - Configuration", () => {
  it("Should throw error if required option is not provided", () => {
    expect(() =>
      Passauth({ ...passauthConfig, secretKey: undefined } as any),
    ).toThrow(PassauthMissingConfigurationException);
    expect(() =>
      Passauth({ ...passauthConfig, secretKey: undefined } as any),
    ).toThrow("Passauth exception: secretKey option is required");

    expect(() =>
      Passauth({ ...passauthConfig, repo: undefined } as any),
    ).toThrow(PassauthMissingConfigurationException);
    expect(() =>
      Passauth({ ...passauthConfig, repo: undefined } as any),
    ).toThrow("Passauth exception: repo option is required");
  });

  it("Should init correctly if only minimun config is provided", () => {
    const passauth = Passauth({
      secretKey: "secretKey",
      repo: repoMock,
    });

    expect(passauth).toBeDefined();
    expect(passauth.handler).toBeDefined();
  });
});
