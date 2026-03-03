/* eslint-disable no-async-promise-executor */
import { Passauth } from "passauth";
import { compareHash, hash } from "passauth/auth/utils";
import { DEFAULT_SALTING_ROUNDS } from "passauth/auth/constants";
import type { AuthRepo } from "passauth/auth/interfaces";
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
  type EmailPluginOptions,
  type SendEmailArgs,
  type UserPluginEmailSender,
} from "../../src/interfaces/types";
import {
  PassauthEmailFailedToSendEmailException,
  PassauthEmailInvalidConfirmEmailTokenException,
  PassauthEmailNotVerifiedException,
} from "../../src/exceptions";
import { EmailSenderPlugin } from "../../src";

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: true,
  isBlocked: false,
};

const repoMock: AuthRepo<UserPluginEmailSender> = {
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

  const emailPluginConfig: EmailPluginOptions = {
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
    plugins: [EmailSenderPlugin(emailPluginConfig)] as const,
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
      ["email"],
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
        senderName: emailPluginConfig.senderName,
        from: emailPluginConfig.senderEmail,
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
    ).rejects.toThrow(PassauthEmailInvalidConfirmEmailTokenException);
  });

  test("confirmEmail - Should call repo.confirmEmail with correct params", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const confirmEmailSpy = jest.spyOn(
      emailPluginConfig.services,
      "createConfirmEmailLink",
    );
    const repoConfirmEmailSpy = jest.spyOn(
      emailPluginConfig.repo,
      "confirmEmail",
    );

    await sut.sendConfirmPasswordEmail(userData.email);

    const token = confirmEmailSpy.mock.calls[0][1];

    await sut.confirmEmail(userData.email, token);

    expect(repoConfirmEmailSpy).toHaveBeenCalledWith(userData.email);
  });

  test("confirmEmail - Should fail if the token is used more than once", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const confirmEmailSpy = jest.spyOn(
      emailPluginConfig.services,
      "createConfirmEmailLink",
    );

    await sut.sendConfirmPasswordEmail(userData.email);

    const token = confirmEmailSpy.mock.calls[0][1];

    await sut.confirmEmail(userData.email, token);

    await expect(sut.confirmEmail(userData.email, token)).rejects.toThrow(
      PassauthEmailInvalidConfirmEmailTokenException,
    );
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
        senderName: emailPluginConfig.senderName,
        from: emailPluginConfig.senderEmail,
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
      emailPluginConfig.services,
      "createResetPasswordLink",
    );
    const repoResetPasswordSpy = jest.spyOn(
      emailPluginConfig.repo,
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
    );

    expect(await compareHash("new-password", hashedPassword)).toBe(true);

    expect(success).toBe(true);
  });
});

describe("Email Plugin:Register", () => {
  class MockEmailClient implements EmailClient {
    async send(_emailData: SendEmailArgs) {}
  }

  const emailClient = new MockEmailClient();

  const emailPluginConfig: EmailPluginOptions = {
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
    plugins: [EmailSenderPlugin(emailPluginConfig)] as const,
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
        senderName: emailPluginConfig.senderName,
        from: emailPluginConfig.senderEmail,
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
