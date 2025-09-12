import bcrypt from "bcrypt";
import { describe, it, expect, jest, beforeEach, test } from "@jest/globals";
import { Passauth } from "../../src/index.js";
import { User } from "../../src/auth/auth.types.js";
import { PassauthEmailAlreadyTakenException } from "../../src/auth/auth.exceptions.js";
import { AuthRepo } from "../../src/auth/auth.types.js";

const repoMock: AuthRepo<User> = {
  getUser: async (email) => null,
  createUser: async (params) => {
    return {
      id: 1,
      email: "user@email.com",
      password: "password123",
    };
  },
};

describe("Passauth:Register - Configuration: minimal", () => {
  const passauthConfig = {
    secretKey: "secretKey",
    saltingRounds: 4,
    repo: repoMock,
  };

  beforeEach(() => {
    jest.restoreAllMocks();
  });

  it("Register - Should throw a error if user already exists", async () => {
    const passauth = Passauth(passauthConfig);

    jest.spyOn(repoMock, "getUser").mockReturnValueOnce(
      new Promise((resolve) =>
        resolve({
          id: 1,
          email: "user@email.com",
          password: "password123",
        })
      )
    );

    const response = passauth.handler.register({
      email: "test@example.com",
      password: "password",
    });

    await expect(response).rejects.toThrow(PassauthEmailAlreadyTakenException);
  });

  it("Register - Should propagate error thrown in dependencies", async () => {
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
      })
    ).rejects.toThrow(CustomError);

    getUserSpy.mockRestore();

    jest.spyOn(repoMock, "createUser").mockRejectedValue(new CustomError());

    await expect(
      passauth.handler.register({
        email: "test@example.com",
        password: "password",
      })
    ).rejects.toThrow(CustomError);
  });

  test("Register - Should pass hashed password to createUser repo", async () => {
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
      })
    );

    const hashedPassword = createUserSpy.mock.calls[0][0].password;

    expect(hashedPassword).not.toBe(registerData.password);

    expect(await bcrypt.compare(registerData.password, hashedPassword)).toBe(
      true
    );
  });
});
