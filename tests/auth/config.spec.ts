/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect } from "@jest/globals";
import { Passauth } from "../../src";
import { PassauthConfiguration, User, AuthRepo } from "../../src/auth/interfaces";
import { PassauthMissingConfigurationException } from "../../src/auth/exceptions";

const repoMock: AuthRepo<User> = {
  getUser: async (_email) => null,
  createUser: async (_params) => {
    return {
      id: 1,
      email: "user@email.com",
      password: "password123",
      isBlocked: false,
      emailVerified: false,
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

describe("Passauth configuration", () => {
  describe("required fields", () => {
    it("throws when secretKey is missing", () => {
      expect(() =>
        Passauth({ ...passauthConfig, secretKey: undefined } as any),
      ).toThrow(PassauthMissingConfigurationException);
      expect(() =>
        Passauth({ ...passauthConfig, secretKey: undefined } as any),
      ).toThrow("Passauth exception: secretKey option is required");
    });

    it("throws when repo is missing", () => {
      expect(() =>
        Passauth({ ...passauthConfig, repo: undefined } as any),
      ).toThrow(PassauthMissingConfigurationException);
      expect(() =>
        Passauth({ ...passauthConfig, repo: undefined } as any),
      ).toThrow("Passauth exception: repo option is required");
    });
  });

  describe("minimal setup", () => {
    it("initializes with only the required configuration", () => {
      const passauth = Passauth({
        secretKey: "secretKey",
        repo: repoMock,
      });

      expect(passauth).toBeDefined();
      expect(passauth.handler).toBeDefined();
    });
  });
});
