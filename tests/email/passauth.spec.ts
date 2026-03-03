import crypto from "crypto";
import {
  Passauth,
  PassauthInvalidAccessTokenException,
  PassauthInvalidRefreshTokenException,
} from "passauth";
import { hash } from "passauth/auth/utils";
import {
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_SALTING_ROUNDS,
} from "passauth/auth/constants";
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

describe("Passauth:Login", () => {
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

  test("VerifyAccessToken - Should throw error if access token is expired", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    jest.advanceTimersByTime(DEFAULT_JWT_EXPIRATION_MS + 1);

    expect(() =>
      passauth.handler.verifyAccessToken(loginResponse.accessToken),
    ).toThrow(PassauthInvalidAccessTokenException);
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

  test("VerifyAccessToken - should return decoded token", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    const decodedToken = passauth.handler.verifyAccessToken(
      loginResponse.accessToken,
    );

    expect(decodedToken).toHaveProperty("sub");
    expect(decodedToken).toHaveProperty("exp");
    expect(decodedToken).toHaveProperty("jti");
    expect(decodedToken).toHaveProperty("iat");

    expect(decodedToken.sub).toBe(userData.id);
  });

  test("RefreshToken - should be able to change tokens", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    const newTokens = await passauth.handler.refreshToken(
      loginResponse.accessToken,
      loginResponse.refreshToken,
    );

    expect(newTokens).toHaveProperty("accessToken");
    expect(newTokens).toHaveProperty("refreshToken");

    expect(loginResponse.accessToken).not.toBe(newTokens.accessToken);
    expect(loginResponse.refreshToken).not.toBe(newTokens.refreshToken);
  });

  test("RefreshToken - Should throw error if refresh token is invalid", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    await expect(
      passauth.handler.refreshToken(
        loginResponse.accessToken,
        crypto.randomBytes(16).toString("hex"),
      ),
    ).rejects.toThrow();
  });

  test("RefreshToken - Should throw error if refresh token is expired", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    jest.advanceTimersByTime(DEFAULT_REFRESH_EXPIRATION_TOKEN_MS + 1);

    await expect(
      passauth.handler.refreshToken(
        loginResponse.accessToken,
        loginResponse.refreshToken,
      ),
    ).rejects.toThrow(PassauthInvalidRefreshTokenException);
  });

  test("RefreshToken - Revoked token should not be able to change tokens", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    passauth.handler.revokeRefreshToken(userData.id);

    await expect(
      passauth.handler.refreshToken(
        loginResponse.accessToken,
        loginResponse.refreshToken,
      ),
    ).rejects.toThrow(PassauthInvalidRefreshTokenException);
  });
});
