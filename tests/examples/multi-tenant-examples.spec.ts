import bcrypt from "bcrypt";
import { describe, expect, it } from "@jest/globals";
import {
  Passauth,
  PassauthEmailAlreadyTakenException,
  PassauthInvalidCredentialsException,
  PassauthPasswordLoginBlockedException,
  type AuthRepo,
  type EmailClient,
  type EmailHandlerOptions,
  type SendEmailArgs,
  type User,
} from "../../src";

type TenantId = "startup" | "enterprise";

type TenantParams = {
  tenantId: TenantId;
};

type TenantUser = User &
  TenantParams & {
    name: string;
  };

class MockEmailClient implements EmailClient {
  async send(_emailData: SendEmailArgs) {}
}

const createMultiTenantExample = () => {
  let nextId = 1;
  const users = new Map<string, TenantUser>();
  const resetTokens = new Map<TenantId, string>();

  const userKey = (email: string, tenantId: TenantId) =>
    `${tenantId}:${email.toLowerCase()}`;

  const repo: AuthRepo<TenantUser> = {
    async getUser(params) {
      const tenantId = (params as Partial<TenantUser>).tenantId;

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

  const email: EmailHandlerOptions = {
    senderName: "Passauth",
    senderEmail: "no-reply@example.com",
    client: new MockEmailClient(),
    services: {
      async createResetPasswordLink(_email, token, linkParams) {
        const tenantId = (linkParams?.tenantId as TenantId | undefined) ?? "startup";

        resetTokens.set(tenantId, token);

        return `https://app.example/reset-password?token=${token}&tenantId=${tenantId}`;
      },
      async createConfirmEmailLink(_email, token, linkParams) {
        return `https://app.example/confirm-email?token=${token}&tenantId=${String(linkParams?.tenantId ?? "")}`;
      },
    },
    repo: {
      async confirmEmail() {
        return true;
      },
      async resetPassword(email, password, emailParams) {
        const tenantId = emailParams?.key as TenantId | undefined;

        if (!tenantId) {
          return false;
        }

        const existingUser = users.get(userKey(email, tenantId));

        if (!existingUser) {
          return false;
        }

        users.set(userKey(email, tenantId), {
          ...existingUser,
          password,
        });

        return true;
      },
    },
  };

  const passauth = Passauth<TenantUser, TenantParams>({
    secretKey: "secret",
    repo,
    email,
    passwordPolicy: {
      rules: {
        minLength: 10,
        maxLength: 64,
        minUppercase: 1,
        minLowercase: 1,
        minNumbers: 1,
        minSpecial: 1,
        maxLoginAttempts: 2,
      },
      resolvePolicy: ({ params, emailParams }) => {
        const tenantId = params?.tenantId ?? (emailParams?.key as TenantId | undefined);

        if (tenantId !== "enterprise") {
          return undefined;
        }

        return {
          rules: {
            minLength: 14,
            maxLength: 64,
            minUppercase: 1,
            minLowercase: 1,
            minNumbers: 1,
            minSpecial: 1,
            maxLoginAttempts: 1,
          },
        };
      },
      resolveLoginAttemptScope: ({ params, emailParams }) =>
        params?.tenantId ?? emailParams?.key,
    },
  });

  return {
    passauth,
    users,
    userKey,
    resetTokens,
  };
};

const registerTenantUsers = async (
  passauth: ReturnType<typeof createMultiTenantExample>["passauth"],
) => {
  await passauth.handler.register({
    email: "john@example.com",
    password: "StartupPass1!",
    name: "John Startup",
    tenantId: "startup",
  });

  await passauth.handler.register({
    email: "john@example.com",
    password: "EnterprisePass1!",
    name: "John Enterprise",
    tenantId: "enterprise",
  });
};

describe("Passauth multi-tenant examples", () => {
  describe("1. tenant-aware registration", () => {
    it("allows the same email in different tenants and preserves duplicate checks inside each tenant", async () => {
      const { passauth } = createMultiTenantExample();

      await registerTenantUsers(passauth);

      await expect(
        passauth.handler.register({
          email: "john@example.com",
          password: "AnotherStartup1!",
          name: "Duplicate Startup",
          tenantId: "startup",
        }),
      ).rejects.toThrow(PassauthEmailAlreadyTakenException);
    });
  });

  describe("2. tenant-aware authentication", () => {
    it("keeps jwt payloads and failed login attempts isolated by tenant", async () => {
      const { passauth } = createMultiTenantExample();

      await registerTenantUsers(passauth);

      const startupTokens = await passauth.handler.login(
        {
          email: "john@example.com",
          password: "StartupPass1!",
          tenantId: "startup",
        },
        { jwtUserFields: ["tenantId", "name"] },
      );

      expect(
        passauth.handler.verifyAccessToken<{
          tenantId: TenantId;
          name: string;
        }>(startupTokens.accessToken).data,
      ).toEqual({
        tenantId: "startup",
        name: "John Startup",
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
        scopeKey: "startup",
        attempts: 1,
        maxLoginAttempts: 2,
        isBlocked: false,
      });

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "enterprise",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "enterprise",
        attempts: 0,
        maxLoginAttempts: 1,
        isBlocked: false,
      });

      await expect(
        passauth.handler.login({
          email: "john@example.com",
          password: "wrong-password",
          tenantId: "enterprise",
        }),
      ).rejects.toThrow(PassauthPasswordLoginBlockedException);

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "enterprise",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "enterprise",
        attempts: 1,
        maxLoginAttempts: 1,
        isBlocked: true,
      });

      await passauth.handler.login({
        email: "john@example.com",
        password: "StartupPass1!",
        tenantId: "startup",
      });

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "startup",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "startup",
        attempts: 0,
        isBlocked: false,
      });

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "enterprise",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "enterprise",
        attempts: 1,
        isBlocked: true,
      });
    });
  });

  describe("3. tenant-aware reset password flow", () => {
    it("uses emailParams.key to isolate reset tokens, passwords and login attempt resets", async () => {
      const { passauth, users, userKey, resetTokens } = createMultiTenantExample();

      await registerTenantUsers(passauth);

      await expect(
        passauth.handler.login({
          email: "john@example.com",
          password: "wrong-password",
          tenantId: "startup",
        }),
      ).rejects.toThrow(PassauthInvalidCredentialsException);

      await expect(
        passauth.handler.login({
          email: "john@example.com",
          password: "wrong-password",
          tenantId: "enterprise",
        }),
      ).rejects.toThrow(PassauthPasswordLoginBlockedException);

      await expect(
        passauth.handler.sendResetPasswordEmail("john@example.com", {
          key: "startup",
          linkParams: {
            tenantId: "startup",
          },
        }),
      ).resolves.toEqual({ success: true });

      await expect(
        passauth.handler.sendResetPasswordEmail("john@example.com", {
          key: "enterprise",
          linkParams: {
            tenantId: "enterprise",
          },
        }),
      ).resolves.toEqual({ success: true });

      const startupToken = resetTokens.get("startup");
      const enterpriseToken = resetTokens.get("enterprise");

      expect(startupToken).toEqual(expect.any(String));
      expect(enterpriseToken).toEqual(expect.any(String));
      expect(startupToken).not.toBe(enterpriseToken);

      await expect(
        passauth.handler.confirmResetPassword(
          "john@example.com",
          startupToken!,
          "NewStartupPass1!",
          {
            key: "startup",
            linkParams: {
              tenantId: "startup",
            },
          },
        ),
      ).resolves.toEqual({ success: true });

      const startupUser = users.get(userKey("john@example.com", "startup"));
      const enterpriseUser = users.get(userKey("john@example.com", "enterprise"));

      expect(startupUser).toBeDefined();
      expect(enterpriseUser).toBeDefined();
      expect(await bcrypt.compare("NewStartupPass1!", startupUser!.password)).toBe(
        true,
      );
      expect(await bcrypt.compare("EnterprisePass1!", enterpriseUser!.password)).toBe(
        true,
      );

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "startup",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "startup",
        attempts: 0,
        isBlocked: false,
      });

      await expect(
        passauth.handler.getLoginAttemptState("john@example.com", {
          params: {
            tenantId: "enterprise",
          },
        }),
      ).resolves.toMatchObject({
        scopeKey: "enterprise",
        attempts: 1,
        isBlocked: true,
      });
    });
  });
});
