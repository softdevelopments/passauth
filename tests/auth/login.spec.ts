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
import { ID, PassauthConfiguration, User } from "../../src/auth/interfaces";
import {
  PassauthInvalidCredentialsException,
  PassauthInvalidUserException,
  PassauthInvalidRefreshTokenException,
  PassauthInvalidAccessTokenException,
  PassauthBlockedUserException,
} from "../../src/auth/exceptions/auth.exceptions";
import { AuthRepo } from "../../src/auth/interfaces";
import { hash } from "../../src/auth/utils/auth.utils";
import {
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_SALTING_ROUNDS,
} from "../../src/auth/constants/auth.constants";

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: false,
  isBlocked: false,
};

describe("Passauth login", () => {
  describe("external repo", () => {
    let cachedToken: {
      [userId: ID]: {
        token: string;
        exp: number;
      };
    } = {};

    const repoMock: AuthRepo<User> = {
      getUser: async (_email) => ({
        ...userData,
        password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
      }),
      createUser: async (_params) => userData,
      getCachedToken: async (userId) => {
        const token = cachedToken[userId];
        const expiration = token?.exp;

        if (!expiration || Date.now() > expiration) {
          return null;
        }

        return token.token;
      },
      saveCachedToken: async (userId, token, expiresInMs) => {
        cachedToken[userId] = { token, exp: Date.now() + expiresInMs };
      },
      deleteCachedToken: async (userId) => {
        delete cachedToken[userId];
      },
    };

    const passauthConfig: PassauthConfiguration<User> = {
      secretKey: "secretKey",
      repo: repoMock,
    };

    describe("cached token", () => {
      beforeAll(() => {
        jest.useFakeTimers();
      });

      beforeEach(() => {
        jest.restoreAllMocks();
        jest.clearAllTimers();
        cachedToken = {};
      });

      test("saves the refresh token in the repository cache", async () => {
        const sut = Passauth(passauthConfig);

        expect(await repoMock.getCachedToken?.(userData.id)).toBeNull();

        const { accessToken, refreshToken } = await sut.handler.login({
          email: userData.email,
          password: userData.password,
        });

        expect(await repoMock.getCachedToken?.(userData.id)).toBeDefined();

        expect(
          await sut.handler.refreshToken(accessToken, refreshToken),
        ).toMatchObject({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
        });
      });

      test("removes the refresh token from the repository cache", async () => {
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

  describe("minimal configuration", () => {
    const repoMock: AuthRepo<User> = {
      getUser: async (_email) => ({
        ...userData,
        password: await hash(userData.password, DEFAULT_SALTING_ROUNDS),
      }),
      createUser: async (_params) => userData,
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

    describe("login", () => {
      test("throws when the user does not exist", () => {
        const passauth = Passauth(passauthConfig);

        jest
          .spyOn(repoMock, "getUser")
          .mockReturnValueOnce(new Promise((resolve) => resolve(null)));

        expect(
          passauth.handler.login({
            email: "user@email.com",
            password: "password123",
          }),
        ).rejects.toThrow(PassauthInvalidUserException);
      });

      test("throws when the password does not match", async () => {
        const passauth = Passauth(passauthConfig);

        await expect(
          passauth.handler.login({
            email: "user@email.com",
            password: "wrongpassword",
          }),
        ).rejects.toThrow(PassauthInvalidCredentialsException);
      });

      test("returns tokens when the credentials are valid", async () => {
        const passauth = Passauth(passauthConfig);

        await expect(
          passauth.handler.login({
            email: userData.email,
            password: userData.password,
          }),
        ).resolves.toEqual({
          accessToken: expect.any(String),
          refreshToken: expect.any(String),
        });
      });

      test("throws when the user is blocked", async () => {
        jest
          .spyOn(repoMock, "getUser")
          .mockImplementationOnce(async () => ({ ...userData, isBlocked: true }));

        const passauth = Passauth(passauthConfig);

        await expect(
          passauth.handler.login({
            email: userData.email,
            password: userData.password,
          }),
        ).rejects.toThrow(PassauthBlockedUserException);
      });

      test("injects user data in the access token when jwtUserFields is provided", async () => {
        const passauth = Passauth(passauthConfig);

        const loginResponse = await passauth.handler.login(
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
    });

    describe("verifyAccessToken", () => {
      test("returns the expected claims", async () => {
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

      test("throws when the access token is expired", async () => {
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

      test("returns the decoded token", async () => {
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
    });

    describe("refreshToken", () => {
      test("rotates the token pair", async () => {
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

      test("throws when the refresh token is invalid", async () => {
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

      test("throws when the refresh token is expired", async () => {
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

      test("throws when the refresh token was revoked", async () => {
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
  });

  describe("extended params", () => {
    type MultiTenantUser = User & {
      username: string;
      tenantId: string;
    };

    const extendedUserData: MultiTenantUser = {
      id: 10,
      email: "tenant-user@email.com",
      username: "tenant-user",
      tenantId: "tenant-1",
      password: "password123",
      emailVerified: false,
      isBlocked: false,
    };

    const repoMock: AuthRepo<MultiTenantUser> = {
      getUser: async (params) => {
        const hasValidCredentials =
          params.email === extendedUserData.email &&
          params.username === extendedUserData.username &&
          params.tenantId === extendedUserData.tenantId;

        if (!hasValidCredentials) {
          return null;
        }

        return {
          ...extendedUserData,
          password: await hash(
            extendedUserData.password,
            DEFAULT_SALTING_ROUNDS,
          ),
        };
      },
      createUser: async (_params) => extendedUserData,
    };

    const passauthConfig: PassauthConfiguration<MultiTenantUser> = {
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

    test("forwards extended params to repo.getUser", async () => {
      const passauth = Passauth(passauthConfig);
      const getUserSpy = jest.spyOn(repoMock, "getUser");

      await expect(
        passauth.handler.login<{ username: string; tenantId: string }>({
          email: extendedUserData.email,
          password: extendedUserData.password,
          username: extendedUserData.username,
          tenantId: extendedUserData.tenantId,
        }),
      ).resolves.toEqual({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      });

      expect(getUserSpy).toHaveBeenCalledWith({
        email: extendedUserData.email,
        password: extendedUserData.password,
        username: extendedUserData.username,
        tenantId: extendedUserData.tenantId,
      });
    });

    test("throws invalid user when the extended params do not match", async () => {
      const passauth = Passauth(passauthConfig);

      await expect(
        passauth.handler.login<{ username: string; tenantId: string }>({
          email: extendedUserData.email,
          password: extendedUserData.password,
          username: extendedUserData.username,
          tenantId: "tenant-2",
        }),
      ).rejects.toThrow(PassauthInvalidUserException);
    });
  });
});
