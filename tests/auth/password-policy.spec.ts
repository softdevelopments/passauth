import { beforeEach, describe, expect, test } from "@jest/globals";
import bcrypt from "bcrypt";
import {
  Passauth,
  PassauthInvalidCredentialsException,
  PassauthPasswordLoginBlockedException,
  PassauthPasswordPolicyConfigurationException,
  PassauthPasswordPolicyException,
  type AuthRepo,
  type PasswordLoginAttemptStore,
  type User,
} from "../../src";
import { hash } from "../../src/auth/utils/auth.utils";

type AppUser = User & {
  name: string;
};

type TenantParams = {
  tenantId: string;
};

type TenantUser = AppUser & TenantParams;

const createBasicRepo = () => {
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
      };

      nextId += 1;
      users.set(user.email, user);

      return user;
    },
  };

  return { repo, users };
};

describe("Passauth password policy integration", () => {
  test("keeps the current register behavior when passwordPolicy is not configured", async () => {
    const { repo } = createBasicRepo();
    const passauth = Passauth({
      secretKey: "secret",
      repo,
    });

    const user = await passauth.handler.register({
      email: "john@example.com",
      password: "weak",
      name: "John",
    });

    expect(user.email).toBe("john@example.com");
  });

  test("applies the default password rules when the feature is enabled", async () => {
    const { repo } = createBasicRepo();
    const passauth = Passauth({
      secretKey: "secret",
      repo,
      passwordPolicy: true,
    });

    await expect(
      passauth.handler.register({
        email: "weak@example.com",
        password: "weak",
        name: "Weak User",
      }),
    ).rejects.toThrow(PassauthPasswordPolicyException);

    const user = await passauth.handler.register({
      email: "strong@example.com",
      password: "Abc1!d",
      name: "Strong User",
    });

    expect(user.email).toBe("strong@example.com");
    expect(await bcrypt.compare("Abc1!d", user.password)).toBe(true);
    expect(passauth.handler.getPasswordPolicy()).toMatchObject({
      minLength: 6,
      maxLength: 12,
      maxLoginAttempts: 3,
      forbidWhitespace: true,
    });
  });

  test("blocks login after the configured number of failed attempts", async () => {
    const password = "StrongPass1!";
    const repo: AuthRepo<AppUser> = {
      async getUser() {
        return {
          id: 1,
          email: "john@example.com",
          password: await hash(password, 10),
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
      async createUser(params) {
        return {
          id: 1,
          email: params.email,
          password: params.password,
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
    };

    const passauth = Passauth({
      secretKey: "secret",
      repo,
      passwordPolicy: true,
    });

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
      }),
    ).rejects.toThrow(PassauthInvalidCredentialsException);

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
      }),
    ).rejects.toThrow(PassauthInvalidCredentialsException);

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
      }),
    ).rejects.toThrow(PassauthPasswordLoginBlockedException);

    await expect(
      passauth.handler.getLoginAttemptState("john@example.com"),
    ).resolves.toEqual({
      email: "john@example.com",
      scopeKey: undefined,
      attempts: 3,
      remainingAttempts: 0,
      isBlocked: true,
      maxLoginAttempts: 3,
    });
  });

  test("resets failed login attempts after a successful login", async () => {
    const password = "StrongPass1!";
    const repo: AuthRepo<AppUser> = {
      async getUser() {
        return {
          id: 1,
          email: "john@example.com",
          password: await hash(password, 10),
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
      async createUser(params) {
        return {
          id: 1,
          email: params.email,
          password: params.password,
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
    };

    const passauth = Passauth({
      secretKey: "secret",
      repo,
      passwordPolicy: {
        rules: {
          maxLoginAttempts: 3,
        },
      },
    });

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
      }),
    ).rejects.toThrow(PassauthInvalidCredentialsException);

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password,
      }),
    ).resolves.toEqual({
      accessToken: expect.any(String),
      refreshToken: expect.any(String),
    });

    await expect(
      passauth.handler.getLoginAttemptState("john@example.com"),
    ).resolves.toEqual({
      email: "john@example.com",
      scopeKey: undefined,
      attempts: 0,
      remainingAttempts: 3,
      isBlocked: false,
      maxLoginAttempts: 3,
    });
  });

  test("supports contextual policy resolution and scoped login attempts", async () => {
    const users = new Map<string, TenantUser>();
    let nextId = 1;
    const userKey = (email: string, tenantId: string) =>
      `${tenantId}:${email.toLowerCase()}`;

    const repo: AuthRepo<TenantUser> = {
      async getUser(params) {
        const tenantId = (params as Partial<TenantUser> & TenantParams).tenantId;

        if (!params.email || !tenantId) {
          return null;
        }

        return users.get(userKey(params.email, tenantId)) ?? null;
      },
      async createUser(params) {
        const tenantId = (params as TenantParams).tenantId;
        const user: TenantUser = {
          id: nextId,
          email: params.email.toLowerCase(),
          password: params.password,
          isBlocked: false,
          emailVerified: true,
          name: (params as { name?: string }).name ?? "John",
          tenantId,
        };

        nextId += 1;
        users.set(userKey(user.email, tenantId), user);

        return user;
      },
    };

    const passauth = Passauth<TenantUser, TenantParams>({
      secretKey: "secret",
      repo,
      passwordPolicy: {
        rules: {
          minLength: 8,
          maxLength: 64,
          minUppercase: 1,
          minLowercase: 1,
          minNumbers: 1,
          minSpecial: 1,
          maxLoginAttempts: 2,
        },
        resolvePolicy: ({ params }) =>
          params?.tenantId === "enterprise"
            ? {
                rules: {
                  minLength: 12,
                  maxLength: 64,
                  minUppercase: 1,
                  minLowercase: 1,
                  minNumbers: 1,
                  minSpecial: 1,
                  maxLoginAttempts: 1,
                },
              }
            : undefined,
        resolveLoginAttemptScope: ({ params, emailParams }) =>
          params?.tenantId ?? emailParams?.key,
      },
    });

    await passauth.handler.register({
      email: "john@example.com",
      password: "Startup1!",
      name: "John Startup",
      tenantId: "startup",
    });

    await expect(
      passauth.handler.register({
        email: "john@example.com",
        password: "Startup1!",
        name: "John Enterprise",
        tenantId: "enterprise",
      }),
    ).rejects.toThrow(PassauthPasswordPolicyException);

    await passauth.handler.register({
      email: "john@example.com",
      password: "EnterprisePass1!",
      name: "John Enterprise",
      tenantId: "enterprise",
    });

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
        tenantId: "startup",
      }),
    ).rejects.toThrow(PassauthInvalidCredentialsException);

    await expect(
      passauth.handler.getLoginAttemptState("john@example.com", {
        params: {
          tenantId: "startup",
        },
      }),
    ).resolves.toMatchObject({
      email: "john@example.com",
      scopeKey: "startup",
      attempts: 1,
      maxLoginAttempts: 2,
    });

    await expect(
      passauth.handler.getLoginAttemptState("john@example.com", {
        params: {
          tenantId: "enterprise",
        },
      }),
    ).resolves.toMatchObject({
      email: "john@example.com",
      scopeKey: "enterprise",
      attempts: 0,
      maxLoginAttempts: 1,
    });
  });

  test("supports an external login attempt store", async () => {
    const externalAttempts = new Map<string, number>();
    const loginAttemptStore: PasswordLoginAttemptStore = {
      async get(email) {
        return externalAttempts.get(email) ?? 0;
      },
      async set(email, attempts) {
        externalAttempts.set(email, attempts);
      },
      async delete(email) {
        externalAttempts.delete(email);
      },
    };

    const password = "StrongPass1!";
    const repo: AuthRepo<AppUser> = {
      async getUser() {
        return {
          id: 1,
          email: "john@example.com",
          password: await hash(password, 10),
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
      async createUser(params) {
        return {
          id: 1,
          email: params.email,
          password: params.password,
          isBlocked: false,
          emailVerified: true,
          name: "John",
        };
      },
    };

    const passauth = Passauth({
      secretKey: "secret",
      repo,
      passwordPolicy: {
        rules: {
          maxLoginAttempts: 2,
        },
        loginAttemptStore,
      },
    });

    await expect(
      passauth.handler.login({
        email: "john@example.com",
        password: "wrong-password",
      }),
    ).rejects.toThrow(PassauthInvalidCredentialsException);

    expect(externalAttempts.get("john@example.com")).toBe(1);
    await expect(
      passauth.handler.getLoginAttemptState("john@example.com"),
    ).resolves.toEqual({
      email: "john@example.com",
      scopeKey: undefined,
      attempts: 1,
      remainingAttempts: 1,
      isBlocked: false,
      maxLoginAttempts: 2,
    });
  });

  test("validates the new password during confirmResetPassword before delegating", async () => {
    const { repo } = createBasicRepo();
    const passauth = Passauth({
      secretKey: "secret",
      repo,
      passwordPolicy: {
        rules: {
          minLength: 12,
          minSpecial: 1,
        },
      },
    });

    await expect(
      passauth.handler.confirmResetPassword(
        "john@example.com",
        "token",
        "Password123",
      ),
    ).rejects.toThrow(PassauthPasswordPolicyException);
  });

  test("rejects invalid password policy configuration during initialization", () => {
    const { repo } = createBasicRepo();

    expect(() =>
      Passauth({
        secretKey: "secret",
        repo,
        passwordPolicy: {} as any,
      }),
    ).toThrow(PassauthPasswordPolicyConfigurationException);

    expect(() =>
      Passauth({
        secretKey: "secret",
        repo,
        passwordPolicy: {
          rules: {
            minLength: 12,
            maxLength: 8,
          },
        },
      }),
    ).toThrow(PassauthPasswordPolicyConfigurationException);
  });
});
