import bcrypt from "bcrypt";
import { describe, it, expect, jest, beforeEach, test } from "@jest/globals";
import { Passauth } from "../../src";
import { User } from "../../src/auth/interfaces";
import { PassauthEmailAlreadyTakenException } from "../../src/auth/exceptions/auth.exceptions.js";
import { AuthRepo } from "../../src/auth/interfaces";

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

describe("Passauth register", () => {
  const passauthConfig = {
    secretKey: "secretKey",
    saltingRounds: 4,
    repo: repoMock,
  };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  describe("minimal configuration", () => {
    it("throws when the user already exists", async () => {
      const passauth = Passauth(passauthConfig);

      jest.spyOn(repoMock, "getUser").mockReturnValueOnce(
        new Promise((resolve) =>
          resolve({
            id: 1,
            email: "user@email.com",
            password: "password123",
            isBlocked: false,
            emailVerified: false,
          }),
        ),
      );

      const response = passauth.handler.register({
        email: "test@example.com",
        password: "password",
      });

      await expect(response).rejects.toThrow(PassauthEmailAlreadyTakenException);
    });

    it("propagates errors thrown by dependencies", async () => {
      class CustomError extends Error {
        constructor() {
          super("Database error");
        }
      }

      const getUserSpy = jest
        .spyOn(repoMock, "getUser")
        .mockRejectedValue(new CustomError());

      const passauth = Passauth(passauthConfig);

      await expect(
        passauth.handler.register({
          email: "test@example.com",
          password: "password",
        }),
      ).rejects.toThrow(CustomError);

      getUserSpy.mockRestore();

      jest.spyOn(repoMock, "createUser").mockRejectedValue(new CustomError());

      await expect(
        passauth.handler.register({
          email: "test@example.com",
          password: "password",
        }),
      ).rejects.toThrow(CustomError);
    });

    test("passes a hashed password to createUser", async () => {
      const passauth = Passauth(passauthConfig);

      const registerData = {
        email: "test@example.com",
        password: "password",
      };

      const createUserSpy = jest.spyOn(repoMock, "createUser");

      await passauth.handler.register(registerData);

      expect(createUserSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          email: registerData.email,
          password: expect.any(String),
        }),
      );

      const hashedPassword = createUserSpy.mock.calls[0][0].password;

      expect(hashedPassword).not.toBe(registerData.password);

      expect(await bcrypt.compare(registerData.password, hashedPassword)).toBe(
        true,
      );
    });
  });

  describe("extended params", () => {
    type ExtendedUser = User & {
      username: string;
      tenantId: string;
    };

    type ExtendedRegisterParams = {
      email: string;
      password: string;
      username: string;
      tenantId: string;
    };

    const extendedRepoMock: AuthRepo<ExtendedUser> = {
      getUser: async (_params) => null,
      createUser: async (params) => {
        const extendedParams = params as ExtendedRegisterParams;

        return {
          id: 10,
          email: extendedParams.email,
          password: extendedParams.password,
          username: extendedParams.username,
          tenantId: extendedParams.tenantId,
          isBlocked: false,
          emailVerified: false,
        };
      },
    };

    const passauthConfig = {
      secretKey: "secretKey",
      saltingRounds: 4,
      repo: extendedRepoMock,
    };

    beforeEach(() => {
      jest.restoreAllMocks();
    });

    test("passes extended params to createUser", async () => {
      const passauth = Passauth(passauthConfig);
      const createUserSpy = jest.spyOn(extendedRepoMock, "createUser");

      const registerData: ExtendedRegisterParams = {
        email: "tenant-user@email.com",
        password: "password123",
        username: "tenant-user",
        tenantId: "tenant-1",
      };

      const register = passauth.handler.register.bind(passauth.handler) as (
        params: ExtendedRegisterParams,
      ) => Promise<ExtendedUser>;

      await register(registerData);

      expect(createUserSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          email: registerData.email,
          username: registerData.username,
          tenantId: registerData.tenantId,
          password: expect.any(String),
        }),
      );

      const createParams = createUserSpy.mock.calls[0][0] as ExtendedRegisterParams;

      expect(createParams.password).not.toBe(registerData.password);
      expect(
        await bcrypt.compare(registerData.password, createParams.password),
      ).toBe(true);
    });

    test("returns the user with extended fields", async () => {
      const passauth = Passauth(passauthConfig);

      const register = passauth.handler.register.bind(passauth.handler) as (
        params: ExtendedRegisterParams,
      ) => Promise<ExtendedUser>;

      const user = await register({
        email: "tenant-user@email.com",
        password: "password123",
        username: "tenant-user",
        tenantId: "tenant-1",
      });

      expect(user).toEqual(
        expect.objectContaining({
          email: "tenant-user@email.com",
          username: "tenant-user",
          tenantId: "tenant-1",
        }),
      );
    });
  });
});
