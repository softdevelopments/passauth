import crypto from "crypto";
import jwt from "jsonwebtoken";
import {
  describe,
  test,
  expect,
  beforeEach,
  jest,
  beforeAll,
} from "@jest/globals";
import { Passauth } from "../../src";
import { ID, PassauthConfiguration, User } from "../../src/auth/auth.types.js";
import {
  PassauthInvalidCredentialsException,
  PassauthInvalidUserException,
  PassauthInvalidRefreshTokenException,
  PassauthInvalidAccessTokenException,
} from "../../src/auth/auth.exceptions";
import { AuthRepo } from "../../src/auth/auth.types.js";
import { hash } from "../../src/auth/auth.utils.js";
import {
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_SALTING_ROUNDS,
} from "../../src/auth/auth.constants.js";

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: false,
};

describe("Passauth:Login - External Repo", () => {
  let cachedToken: {
    [userId: ID]: {
      token: string;
      exp: number;
    };
  } = {};

  const repoMock: AuthRepo<User> = {
    getUser: async (email) => ({
      ...userData,
      password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
    }),
    createUser: async (params) => userData,
    getCachedToken: async (userId) => {
      const token = cachedToken[userId];

      const expiration = token?.exp;

      if (!expiration || Date.now() > expiration) {
        return null;
      }

      return token?.token;
    },
    saveCachedToken: async (userId, token, expiresInMs) => {
      cachedToken[userId] = { token, exp: expiresInMs };
    },
    deleteCachedToken: async (userId) => {
      delete cachedToken[userId];
    },
  };

  const passauthConfig: PassauthConfiguration<User> = {
    secretKey: "secretKey",
    repo: repoMock,
  };

  describe("Cached Token", () => {
    beforeAll(() => {
      jest.useFakeTimers();
    });

    beforeEach(() => {
      jest.restoreAllMocks();
      jest.clearAllTimers();
      cachedToken = {};
    });

    test("Should get saved refresh token", async () => {
      const sut = Passauth(passauthConfig);

      expect(await repoMock.getCachedToken?.(userData.id)).toBeNull();

      const { accessToken, refreshToken } = await sut.handler.login({
        email: userData.email,
        password: userData.password,
      });

      expect(await repoMock.getCachedToken?.(userData.id)).toBeDefined();

      expect(
        await sut.handler.refreshToken(accessToken, refreshToken)
      ).toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      });
    });

    test("Should delete cached token", async () => {
      const sut = Passauth(passauthConfig);

      expect(await repoMock.getCachedToken?.(userData.id)).toBeNull();

      await sut.handler.login({
        email: userData.email,
        password: userData.password,
      });

      expect(await repoMock.getCachedToken?.(userData.id)).toBeDefined();

      await sut.handler.revokeRefreshToken(userData.id);

      expect(cachedToken[userData.id]).toBeUndefined();
    });
  });
});

describe("Passauth:Login - Configuration: minimal", () => {
  const repoMock: AuthRepo<User> = {
    getUser: async (email) => ({
      ...userData,
      password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
    }),
    createUser: async (params) => userData,
  };

  const passauthConfig: PassauthConfiguration<User> = {
    secretKey: "secretKey",
    repo: repoMock,
  };

  beforeAll(() => {
    jest.useFakeTimers();
  });

  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllTimers();
  });

  test("Login - Should throw error if user does not exist", () => {
    const passauth = Passauth(passauthConfig);

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));

    expect(
      passauth.handler.login({
        email: "user@email.com",
        password: "password123",
      })
    ).rejects.toThrow(PassauthInvalidUserException);
  });

  test("Login - Should throw error if passwords don't match", async () => {
    const passauth = Passauth(passauthConfig);

    await expect(
      passauth.handler.login({
        email: "user@email.com",
        password: "wrongpassword",
      })
    ).rejects.toThrow(PassauthInvalidCredentialsException);
  });

  test("Login - Should return tokens if credentials are valid", async () => {
    const passauth = Passauth(passauthConfig);

    await expect(
      passauth.handler.login({
        email: userData.email,
        password: userData.password,
      })
    ).resolves.toEqual({
      accessToken: expect.any(String),
      refreshToken: expect.any(String),
    });
  });

  test("Login - Access token should have correct claims", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    const decodedToken = jwt.decode(loginResponse.accessToken);

    expect(Object.keys(decodedToken!)).toHaveLength(4);
    expect(decodedToken).toHaveProperty("sub");
    expect(decodedToken).toHaveProperty("exp");
    expect(decodedToken).toHaveProperty("jti");
    expect(decodedToken).toHaveProperty("iat");

    expect(decodedToken?.sub).toBe(userData.id);
  });

  test("Login - Access token should inject user data when jwtUserFields is provided", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login(
      {
        email: userData.email,
        password: userData.password,
      },
      ["email"]
    );

    const decodedToken = passauth.handler.verifyAccessToken(
      loginResponse.accessToken
    );

    expect(decodedToken).toEqual(
      expect.objectContaining({
        data: {
          email: userData.email,
        },
      })
    );
  });

  test("VerifyAccessToken - Should throw error if access token is expired", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    jest.advanceTimersByTime(DEFAULT_JWT_EXPIRATION_MS + 1);

    expect(() =>
      passauth.handler.verifyAccessToken(loginResponse.accessToken)
    ).toThrow(PassauthInvalidAccessTokenException);
  });

  test("VerifyAccessToken - should return decoded token", async () => {
    const passauth = Passauth(passauthConfig);

    const loginResponse = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    const decodedToken = passauth.handler.verifyAccessToken(
      loginResponse.accessToken
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
      loginResponse.refreshToken
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
        crypto.randomBytes(16).toString("hex")
      )
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
        loginResponse.refreshToken
      )
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
        loginResponse.refreshToken
      )
    ).rejects.toThrow(PassauthInvalidRefreshTokenException);
  });
});
