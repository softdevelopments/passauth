import bcrypt from "bcrypt";
import { describe, expect, it } from "@jest/globals";
import {
  Passauth,
  PassauthInvalidCredentialsException,
  PassauthPasswordLoginBlockedException,
  PassauthPasswordPolicyException,
  type AuthRepo,
  type User,
} from "../../src";

type AppUser = User & {
  name: string;
  role: "admin" | "member";
};

const createExampleRepo = () => {
  let nextId = 1;
  const users = new Map<string, AppUser>();

  const repo: AuthRepo<AppUser> = {
    async getUser(params) {
      if (!params.email) {
        return null;
      }

      return users.get(params.email.toLowerCase()) ?? null;
    },
    async createUser(params) {
      const user: AppUser = {
        id: nextId,
        email: params.email.toLowerCase(),
        password: params.password,
        isBlocked: false,
        emailVerified: true,
        name: (params as { name?: string }).name ?? "John",
        role: (params as { role?: AppUser["role"] }).role ?? "member",
      };

      nextId += 1;
      users.set(user.email, user);

      return user;
    },
  };

  return { repo, users };
};

describe("Passauth core examples", () => {
  describe("1. default configuration", () => {
    it("supports register, login and custom jwt fields in a typical app flow", async () => {
      const { repo } = createExampleRepo();
      const passauth = Passauth<AppUser>({
        secretKey: "secret",
        repo,
      });

      const user = await passauth.handler.register({
        email: "john@example.com",
        password: "Simple123",
        name: "John",
        role: "admin",
      });

      expect(user).toEqual(
        expect.objectContaining({
          email: "john@example.com",
          name: "John",
          role: "admin",
        }),
      );
      expect(await bcrypt.compare("Simple123", user.password)).toBe(true);

      const tokens = await passauth.handler.login(
        {
          email: "john@example.com",
          password: "Simple123",
        },
        { jwtUserFields: ["email", "name", "role"] },
      );

      expect(tokens).toEqual({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      });

      const payload = passauth.handler.verifyAccessToken<{
        email: string;
        name: string;
        role: AppUser["role"];
      }>(tokens.accessToken);

      expect(payload.data).toEqual({
        email: "john@example.com",
        name: "John",
        role: "admin",
      });
    });
  });

  describe("2. Password policies", () => {
    it("validates custom rules and blocks repeated failed logins", async () => {
      const { repo } = createExampleRepo();
      const passauth = Passauth<AppUser>({
        secretKey: "secret",
        repo,
        passwordPolicy: {
          rules: {
            minLength: 10,
            maxLength: 64,
            minUppercase: 1,
            minLowercase: 1,
            minNumbers: 1,
            minSpecial: 1,
            maxLoginAttempts: 2,
            forbidWhitespace: true,
          },
        },
      });

      await expect(
        passauth.handler.register({
          email: "weak@example.com",
          password: "weak",
          name: "Weak User",
          role: "member",
        }),
      ).rejects.toThrow(PassauthPasswordPolicyException);

      await passauth.handler.register({
        email: "strong@example.com",
        password: "StrongPass1!",
        name: "Strong User",
        role: "member",
      });

      expect(
        passauth.handler.validatePassword("StrongPass1!"),
      ).toMatchObject({
        success: true,
      });
      expect(passauth.handler.getPasswordPolicy()).toMatchObject({
        minLength: 10,
        maxLoginAttempts: 2,
      });

      await expect(
        passauth.handler.login({
          email: "strong@example.com",
          password: "wrong-password",
        }),
      ).rejects.toThrow(PassauthInvalidCredentialsException);

      await expect(
        passauth.handler.login({
          email: "strong@example.com",
          password: "wrong-password",
        }),
      ).rejects.toThrow(PassauthPasswordLoginBlockedException);

      await expect(
        passauth.handler.getLoginAttemptState("strong@example.com"),
      ).resolves.toEqual({
        email: "strong@example.com",
        scopeKey: undefined,
        attempts: 2,
        remainingAttempts: 0,
        isBlocked: true,
        maxLoginAttempts: 2,
      });
    });
  });
});
