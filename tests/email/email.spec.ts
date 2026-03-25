/* eslint-disable no-async-promise-executor */
import { Passauth } from "../../src";
import { compareHash, hash } from "../../src/auth/utils/auth.utils";
import {
  describe,
  test,
  expect,
  beforeEach,
  jest,
  beforeAll,
} from "@jest/globals";
import {
  type EmailClient,
  type EmailHandlerOptions,
  type SendEmailArgs,
} from "../../src/auth/interfaces";
import { User, AuthRepo } from "../../src/auth/interfaces";
import {
  PassauthEmailFailedToSendEmailException,
  PassauthInvalidConfirmEmailTokenException,
  PassauthEmailNotVerifiedException,
} from "../../src/auth/exceptions";
import { DEFAULT_SALTING_ROUNDS } from "../../src";

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: true,
  isBlocked: false,
};

const repoMock: AuthRepo<User> = {
  getUser: async (_email) => ({
    ...userData,
    password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
  }),
  createUser: async (_params) => userData,
};

describe("Email Plugin:Login", () => {
  class MockEmailClient implements EmailClient {
    async send(_emailData: SendEmailArgs) {}
  }

  const emailClient = new MockEmailClient();

  const emailHandlerConfig: EmailHandlerOptions = {
    senderName: "Sender Name",
    senderEmail: "sender@example.com",
    client: emailClient,
    services: {
      createResetPasswordLink: async (email: string, token: string) =>
        `http://mysite.com/reset-password?token=${token}`,
      createConfirmEmailLink: async (email: string, token: string) =>
        `http://mysite.com/confirm-email?token=${token}`,
    },
    repo: {
      confirmEmail: async (_email: string) => true,
      resetPassword: async (_email: string, _password: string) => true,
    },
  };

  const passauthConfig = {
    secretKey: "secretKey",
    repo: repoMock,
    email: emailHandlerConfig,
  };

  beforeAll(() => {
    jest.useFakeTimers();
  });

  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllTimers();
  });

  test("login - User should not authenticate if email is not confirmed", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    jest.spyOn(repoMock, "getUser").mockReturnValueOnce(
      new Promise(async (resolve) =>
        resolve({
          ...userData,
          isBlocked: false,
          password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
          emailVerified: false,
        }),
      ),
    );

    await expect(
      sut.login({
        email: userData.email,
        password: userData.password,
      }),
    ).rejects.toThrow(PassauthEmailNotVerifiedException);
  });

  test("login - User should authenticate if email is confirmed", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const tokens = await sut.login({
      email: userData.email,
      password: userData.password,
    });

    expect(tokens).toHaveProperty("accessToken");
    expect(tokens).toHaveProperty("refreshToken");

    expect(passauth.handler.verifyAccessToken(tokens.accessToken).sub).toBe(
      userData.id,
    );
  });

  test("Login - Access token should inject user data when jwtUserFields is provided", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const loginResponse = await sut.login(
      {
        email: userData.email,
        password: userData.password,
      },
      { jwtUserFields: ["email"] },
    );

    const decodedToken = passauth.handler.verifyAccessToken(
      loginResponse.accessToken,
    );

    expect(decodedToken).toEqual(
      expect.objectContaining({
        data: {
          email: userData.email,
        },
      }),
    );
  });

  test("sendConfirmPasswordEmail - User should receive email with confirmation link", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const emailSenderSpy = jest.spyOn(emailClient, "send");

    const { success } = await sut.sendConfirmPasswordEmail(userData.email);

    expect(emailSenderSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        senderName: emailHandlerConfig.senderName,
        from: emailHandlerConfig.senderEmail,
        to: [userData.email],
        subject: "Confirm your email",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );

    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "http://mysite.com/confirm-email?token=",
    );
    expect(emailSenderSpy.mock.calls[0][0].html).toMatch(
      /<a href="http:\/\/mysite\.com\/confirm-email\?token=\w+">Confirm email<\/a>/,
    );
    expect(success).toBe(true);
  });

  test("sendConfirmPasswordEmail - Should pass emailParams.linkParams to confirmation link builder", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const linkParams = {
      redirectTo: "/settings/security",
      source: "email-confirmation",
    };

    const createConfirmEmailLinkSpy = jest
      .spyOn(emailHandlerConfig.services, "createConfirmEmailLink")
      .mockImplementationOnce(async (_email, token, params) => {
        const query = new URLSearchParams({
          token,
          ...Object.fromEntries(
            Object.entries((params ?? {}) as Record<string, unknown>).map(([key, value]) => [
              key,
              String(value),
            ]),
          ),
        });

        return `http://mysite.com/confirm-email?${query.toString()}`;
      });
    const emailSenderSpy = jest.spyOn(emailClient, "send");

    const { success } = await sut.sendConfirmPasswordEmail(userData.email, {
      linkParams,
    });

    expect(createConfirmEmailLinkSpy).toHaveBeenCalledWith(
      userData.email,
      expect.any(String),
      linkParams,
    );
    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "redirectTo=%2Fsettings%2Fsecurity",
    );
    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "source=email-confirmation",
    );
    expect(success).toBe(true);
  });

  test("sendConfirmPasswordEmail - Should throw error if the email fails to send", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    jest
      .spyOn(emailClient, "send")
      .mockReturnValueOnce(
        new Promise((_, reject) => reject(new Error("Email send failed"))),
      );

    await expect(sut.sendConfirmPasswordEmail(userData.email)).rejects.toThrow(
      PassauthEmailFailedToSendEmailException,
    );
  });

  test("confirmEmail - Should fail if the token is invalid", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    await expect(
      sut.confirmEmail(userData.email, "invalid-token"),
    ).rejects.toThrow(PassauthInvalidConfirmEmailTokenException);
  });

  test("confirmEmail - Should call repo.confirmEmail with correct params", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );
    const repoConfirmEmailSpy = jest.spyOn(
      emailHandlerConfig.repo,
      "confirmEmail",
    );

    await sut.sendConfirmPasswordEmail(userData.email);

    const token = confirmEmailSpy.mock.calls[0][1];

    await sut.confirmEmail(userData.email, token);

    expect(repoConfirmEmailSpy).toHaveBeenCalledWith(userData.email, undefined);
  });

  test("confirmEmail - Should pass emailParams to repo.confirmEmail", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const emailParams = {
      linkParams: {
        redirectTo: "/settings/security",
        source: "email-confirmation",
      },
    };

    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );
    const repoConfirmEmailSpy = jest.spyOn(
      emailHandlerConfig.repo,
      "confirmEmail",
    );

    await sut.sendConfirmPasswordEmail(userData.email, emailParams);

    const token = confirmEmailSpy.mock.calls[0][1];

    await sut.confirmEmail(userData.email, token, emailParams);

    expect(repoConfirmEmailSpy).toHaveBeenCalledWith(userData.email, emailParams);
  });

  test("confirmEmail - Should fail if the token is used more than once", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );

    await sut.sendConfirmPasswordEmail(userData.email);

    const token = confirmEmailSpy.mock.calls[0][1];

    await sut.confirmEmail(userData.email, token);

    await expect(sut.confirmEmail(userData.email, token)).rejects.toThrow(
      PassauthInvalidConfirmEmailTokenException,
    );
  });

  test("confirmEmail - Should invalidate the previous token when a new token is generated with the same key", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );
    const emailParams = {
      key: "tenant-a",
      linkParams: { tenantId: "tenant-a" },
    };

    await sut.sendConfirmPasswordEmail(userData.email, emailParams);
    const firstToken = confirmEmailSpy.mock.calls[0][1];

    await sut.sendConfirmPasswordEmail(userData.email, emailParams);
    const secondToken = confirmEmailSpy.mock.calls[1][1];

    await expect(
      sut.confirmEmail(userData.email, firstToken, { key: "tenant-a" }),
    ).rejects.toThrow(PassauthInvalidConfirmEmailTokenException);
    await expect(
      sut.confirmEmail(userData.email, secondToken, { key: "tenant-a" }),
    ).resolves.toBeUndefined();
  });

  test("confirmEmail - Should keep tokens isolated by key for the same email", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );
    const repoConfirmEmailSpy = jest.spyOn(
      emailHandlerConfig.repo,
      "confirmEmail",
    );

    await sut.sendConfirmPasswordEmail(userData.email, {
      key: "tenant-a",
      linkParams: { tenantId: "tenant-a" },
    });
    const firstToken = confirmEmailSpy.mock.calls[0][1];

    await sut.sendConfirmPasswordEmail(userData.email, {
      key: "tenant-b",
      linkParams: { tenantId: "tenant-b" },
    });
    const secondToken = confirmEmailSpy.mock.calls[1][1];

    await expect(
      sut.confirmEmail(userData.email, firstToken, { key: "tenant-a" }),
    ).resolves.toBeUndefined();
    await expect(
      sut.confirmEmail(userData.email, secondToken, { key: "tenant-b" }),
    ).resolves.toBeUndefined();
    expect(repoConfirmEmailSpy).toHaveBeenCalledTimes(2);
  });

  test("confirmEmail - Should default the token key to the email when key is not provided", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const confirmEmailSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createConfirmEmailLink",
    );

    await sut.sendConfirmPasswordEmail(userData.email);
    const firstToken = confirmEmailSpy.mock.calls[0][1];

    await sut.sendConfirmPasswordEmail(userData.email);
    const secondToken = confirmEmailSpy.mock.calls[1][1];

    await expect(sut.confirmEmail(userData.email, firstToken)).rejects.toThrow(
      PassauthInvalidConfirmEmailTokenException,
    );
    await expect(sut.confirmEmail(userData.email, secondToken)).resolves.toBeUndefined();
  });

  test("sendResetPasswordEmail - Should pass correct params to email sender", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    const emailSenderSpy = jest.spyOn(emailClient, "send");

    await sut.sendResetPasswordEmail(userData.email);

    expect(emailSenderSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        senderName: emailHandlerConfig.senderName,
        from: emailHandlerConfig.senderEmail,
        to: [userData.email],
        subject: "Reset Password",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );

    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "http://mysite.com/reset-password?token=",
    );
    expect(emailSenderSpy.mock.calls[0][0].html).toMatch(
      /<a href="http:\/\/mysite\.com\/reset-password\?token=\w+">Reset password<\/a>/,
    );
  });

  test("sendResetPasswordEmail - Should pass emailParams.linkParams to reset link builder", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const emailParams = {
      linkParams: {
        redirectTo: "/settings/security",
        source: "password-reset",
      },
    };

    const createResetPasswordLinkSpy = jest
      .spyOn(emailHandlerConfig.services, "createResetPasswordLink")
      .mockImplementationOnce(async (_email, token, params) => {
        const query = new URLSearchParams({
          token,
          ...Object.fromEntries(
            Object.entries((params ?? {}) as Record<string, unknown>).map(([key, value]) => [
              key,
              String(value),
            ]),
          ),
        });

        return `http://mysite.com/reset-password?${query.toString()}`;
      });
    const emailSenderSpy = jest.spyOn(emailClient, "send");

    const { success } = await sut.sendResetPasswordEmail(userData.email, emailParams);

    expect(createResetPasswordLinkSpy).toHaveBeenCalledWith(
      userData.email,
      expect.any(String),
      emailParams.linkParams,
    );
    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "redirectTo=%2Fsettings%2Fsecurity",
    );
    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "source=password-reset",
    );
    expect(success).toBe(true);
  });

  test("confirmResetPassword - Should fail if token is invalid", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    expect(
      await sut.confirmResetPassword(
        userData.email,
        "invalid-token",
        "new-password",
      ),
    ).toEqual({ success: false });

    await sut.sendResetPasswordEmail(userData.email);

    expect(
      await sut.confirmResetPassword(
        userData.email,
        "invalid-token",
        "new-password",
      ),
    ).toEqual({ success: false });
  });

  test("confirmResetPassword - Should pass correct params to repo.resetPassword", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const resetPasswordSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createResetPasswordLink",
    );
    const repoResetPasswordSpy = jest.spyOn(
      emailHandlerConfig.repo,
      "resetPassword",
    );
    await sut.sendResetPasswordEmail(userData.email);

    const token = resetPasswordSpy.mock.calls[0][1];

    const { success } = await sut.confirmResetPassword(
      userData.email,
      token,
      "new-password",
    );
    const hashedPassword = repoResetPasswordSpy.mock.calls[0][1];

    expect(repoResetPasswordSpy).toHaveBeenCalledWith(
      userData.email,
      expect.any(String),
      undefined,
    );

    expect(await compareHash("new-password", hashedPassword)).toBe(true);

    expect(success).toBe(true);
  });

  test("confirmResetPassword - Should pass emailParams to repo.resetPassword", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const emailParams = {
      linkParams: {
        redirectTo: "/settings/security",
        source: "password-reset",
      },
    };

    const resetPasswordSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createResetPasswordLink",
    );
    const repoResetPasswordSpy = jest.spyOn(
      emailHandlerConfig.repo,
      "resetPassword",
    );

    await sut.sendResetPasswordEmail(userData.email, emailParams);

    const token = resetPasswordSpy.mock.calls[0][1];

    const { success } = await sut.confirmResetPassword(
      userData.email,
      token,
      "new-password",
      emailParams,
    );

    expect(repoResetPasswordSpy).toHaveBeenCalledWith(
      userData.email,
      expect.any(String),
      emailParams,
    );
    expect(success).toBe(true);
  });

  test("confirmResetPassword - Should invalidate the previous token when a new token is generated with the same key", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const resetPasswordSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createResetPasswordLink",
    );
    const emailParams = {
      key: "tenant-a",
      linkParams: { tenantId: "tenant-a" },
    };

    await sut.sendResetPasswordEmail(userData.email, emailParams);
    const firstToken = resetPasswordSpy.mock.calls[0][1];

    await sut.sendResetPasswordEmail(userData.email, emailParams);
    const secondToken = resetPasswordSpy.mock.calls[1][1];

    await expect(
      sut.confirmResetPassword(userData.email, firstToken, "new-password-a", {
        key: "tenant-a",
      }),
    ).resolves.toEqual({ success: false });
    await expect(
      sut.confirmResetPassword(userData.email, secondToken, "new-password-b", {
        key: "tenant-a",
      }),
    ).resolves.toEqual({ success: true });
  });

  test("confirmResetPassword - Should keep tokens isolated by key for the same email", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;
    const resetPasswordSpy = jest.spyOn(
      emailHandlerConfig.services,
      "createResetPasswordLink",
    );

    await sut.sendResetPasswordEmail(userData.email, {
      key: "tenant-a",
      linkParams: { tenantId: "tenant-a" },
    });
    const firstToken = resetPasswordSpy.mock.calls[0][1];

    await sut.sendResetPasswordEmail(userData.email, {
      key: "tenant-b",
      linkParams: { tenantId: "tenant-b" },
    });
    const secondToken = resetPasswordSpy.mock.calls[1][1];

    await expect(
      sut.confirmResetPassword(userData.email, firstToken, "new-password-a", {
        key: "tenant-a",
      }),
    ).resolves.toEqual({ success: true });
    await expect(
      sut.confirmResetPassword(userData.email, secondToken, "new-password-b", {
        key: "tenant-b",
      }),
    ).resolves.toEqual({ success: true });
  });
});

describe("Email Plugin:Register", () => {
  class MockEmailClient implements EmailClient {
    async send(_emailData: SendEmailArgs) {}
  }

  const emailClient = new MockEmailClient();

  const emailHandlerConfig: EmailHandlerOptions = {
    senderName: "Sender Name",
    senderEmail: "sender@example.com",
    client: emailClient,
    services: {
      createResetPasswordLink: async (email: string, token: string) =>
        `http://mysite.com/reset-password?token=${token}`,
      createConfirmEmailLink: async (email: string, token: string) =>
        `http://mysite.com/confirm-email?token=${token}`,
    },
    repo: {
      confirmEmail: async (_email: string) => true,
      resetPassword: async (_email: string, _password: string) => true,
    },
  };

  const passauthConfig = {
    secretKey: "secretKey",
    repo: repoMock,
    email: emailHandlerConfig
  };

  const userData = {
    id: 1,
    email: "user@email.com",
    password: "password123",
    emailVerified: false,
  };

  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllTimers();
  });

  test("register - Returns throws error when the email fails to send", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    jest.spyOn(emailClient, "send").mockImplementationOnce(() => {
      throw new Error("Email send failed");
    });

    await expect(
      sut.register({
        email: userData.email,
        password: userData.password,
      }),
    ).rejects.toThrow(PassauthEmailFailedToSendEmailException);
  });

  test("register - User should receive confirmation email", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    const emailSenderSpy = jest.spyOn(emailClient, "send");

    await sut.register({
      email: userData.email,
      password: userData.password,
    });

    expect(emailSenderSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        senderName: emailHandlerConfig.senderName,
        from: emailHandlerConfig.senderEmail,
        to: [userData.email],
        subject: "Confirm your email",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );

    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "http://mysite.com/confirm-email?token=",
    );
    expect(emailSenderSpy.mock.calls[0][0].html).toMatch(
      /<a href="http:\/\/mysite\.com\/confirm-email\?token=\w+">Confirm email<\/a>/,
    );
  });
});
