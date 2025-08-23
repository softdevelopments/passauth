import bcrypt from "bcrypt";
import { describe, it, expect, jest, beforeEach, test } from "@jest/globals";
import { Passauth } from "../../src";
import { PassauthConfiguration, User } from "../../src/auth/auth.types";
import {
  PassauthEmailAlreadyTakenException,
  PassauthEmailSenderRequiredException,
} from "../../src/auth/auth.exceptions";
import { AuthRepo } from "../../src/auth/auth.types";
import { EmailClient, SendEmailArgs } from "../../src/email/email.types";

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

  test("Confirm Password - Should throw error if email sender is not provided", async () => {
    const passauth = Passauth(passauthConfig);

    await expect(
      passauth.handler.confirmEmail("user@email.com", "token")
    ).rejects.toThrow(PassauthEmailSenderRequiredException);
  });
});

describe("Passauth:Register -  Configuration: email provider and email confirmation", () => {
  class MockEmailClient implements EmailClient {
    async send(emailData: SendEmailArgs) {}
  }

  const emailClient = new MockEmailClient();

  const passauthConfig: PassauthConfiguration<User> = {
    secretKey: "secretKey",
    repo: repoMock,
    requireEmailConfirmation: true,
    emailPlugin: {
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
        confirmEmail: async (email: string) => true,
        resetPassword: async (email: string, password: string) => true,
      },
    },
  };

  const userData = {
    id: 1,
    email: "user@email.com",
    password: "password123",
    emailVerified: false,
  };

  test("Register - Should return emailSent equals false if email fails", async () => {
    const passauth = Passauth(passauthConfig);

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    jest.spyOn(emailClient, "send").mockImplementationOnce(() => {
      throw new Error("Email send failed");
    });

    const { emailSent } = await passauth.handler.register({
      email: userData.email,
      password: userData.password,
    });

    expect(emailSent).toBe(false);
  });

  test("Register - Should pass correct params to email sender", async () => {
    const passauth = Passauth(passauthConfig);

    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    const emailSenderSpy = jest.spyOn(emailClient, "send");

    await passauth.handler.register({
      email: userData.email,
      password: userData.password,
    });

    expect(emailSenderSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        senderName: passauthConfig.emailPlugin?.senderName,
        from: passauthConfig.emailPlugin?.senderEmail,
        to: [userData.email],
        subject: "Confirm your email",
        text: expect.any(String),
        html: expect.any(String),
      })
    );

    expect(emailSenderSpy.mock.calls[0][0].text).toContain(
      "http://mysite.com/confirm-email?token="
    );
    expect(emailSenderSpy.mock.calls[0][0].html).toMatch(
      /<a href="http:\/\/mysite\.com\/confirm-email\?token=\w+\">Confirm email\<\/a>/
    );
  });
});
