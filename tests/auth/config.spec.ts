import { describe, it, expect, jest, beforeEach } from "@jest/globals";
import { Passauth } from "../../dist";
import { PassauthConfiguration, User } from "../../dist/auth/auth.types";
import {
  PassauthEmailAlreadyTakenException,
  PassauthMissingConfigurationException,
} from "../../dist/auth/auth.exceptions";
import { AuthRepo } from "../../dist/auth/auth.types";

const repoMock: AuthRepo<User> = {
  getUser: async (email) => null,
  createUser: async (params) => {
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
  requireEmailConfirmation: false,
  repo: repoMock,
};

describe("Passauth - Configuration", () => {
  it("Should throw error if required option is not provided", () => {
    expect(() =>
      Passauth({ ...passauthConfig, secretKey: undefined } as any)
    ).toThrow(PassauthMissingConfigurationException);
    expect(() =>
      Passauth({ ...passauthConfig, secretKey: undefined } as any)
    ).toThrow("Passauth exception: secretKey option is required");

    expect(() =>
      Passauth({ ...passauthConfig, requireEmailConfirmation: true } as any)
    ).toThrow(PassauthMissingConfigurationException);
    expect(() =>
      Passauth({ ...passauthConfig, requireEmailConfirmation: true } as any)
    ).toThrow("Passauth exception: emailPlugin option is required");

    expect(() =>
      Passauth({ ...passauthConfig, repo: undefined } as any)
    ).toThrow(PassauthMissingConfigurationException);
    expect(() =>
      Passauth({ ...passauthConfig, repo: undefined } as any)
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
