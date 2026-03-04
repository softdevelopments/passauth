/* eslint-disable @typescript-eslint/no-explicit-any */
import { beforeAll, beforeEach, describe, expect, jest, test } from "@jest/globals";
import { Passauth } from "../../src";
import {
  PassauthConfiguration,
  User,
  AuthRepo,
} from "../../src/auth/types/auth.types";
import { TemplateTypes } from "../../src/auth/email.enum";
import {
  EmailClient,
  EmailHandlerOptions,
  SendEmailArgs,
} from "../../src/auth/types";
import { PassauthEmailMissingConfigurationException, PassauthInvalidConfirmEmailTokenException } from "../../src/auth/exceptions";


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

const passauthConfig: PassauthConfiguration<User> = {
  secretKey: "secretKey",
  saltingRounds: 4,
  accessTokenExpirationMs: 1000 * 60,
  refreshTokenExpirationMs: 1000 * 60 * 15,
  repo: repoMock,
};

class MockEmailClient implements EmailClient {
  async send(_emailData: SendEmailArgs) {}
}

const emailClient = new MockEmailClient();

const emailConfig: EmailHandlerOptions = {
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

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: true,
  isBlocked: false,
};

describe("Email Sender - Configuration", () => {
  test("Should throw error if required option is not provided", () => {
    // Option senderName
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, senderName: undefined },
      } as any),
    ).toThrow(PassauthEmailMissingConfigurationException);
    // Option senderEmail
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, senderEmail: undefined },
      } as any),
    ).toThrow(PassauthEmailMissingConfigurationException);
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, senderEmail: undefined },
      } as any),
    ).toThrow("senderEmail option is required");

    // Option client
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, client: undefined },
      } as any),
    ).toThrow(PassauthEmailMissingConfigurationException);
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, client: undefined },
      } as any),
    ).toThrow("client option is required");

    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, services: undefined },
      } as any),
    ).toThrow(PassauthEmailMissingConfigurationException);
    expect(() =>
      Passauth({
        ...passauthConfig,
        email: { ...emailConfig, services: undefined },
      } as any),
    ).toThrow("services option is required");
  });

  test("Should init correctly if only minimum config is provided", () => {
    const passauth = Passauth({
      ...passauthConfig,
      email: emailConfig,
    } as any);

    expect(passauth).toBeDefined();
    expect(passauth.handler).toBeDefined();
  });
});

describe("Email:Options:Templates", () => {
  const passauthConfig = {
    secretKey: "secretKey",
    repo: repoMock,
    email: {
      ...emailConfig,
      templates: {
        [TemplateTypes.CONFIRM_EMAIL]: (params) => ({
          text: `This is the confirm email template for email: ${params.email}, link: ${params.link}`,
          html: `This is the confirm email template for email: ${params.email}, <a href="${params.link}">link</a>`,
        }),
        [TemplateTypes.RESET_PASSWORD]: (params) => ({
          text: `This is the reset password template for email: ${params.email}, link: ${params.link}`,
          html: `This is the reset password template for email: ${params.email}, <a href="${params.link}">link</a>`,
        }),
      },
    },
  } as PassauthConfiguration<User>;

  beforeEach(() => {
    jest.restoreAllMocks();
    jest.clearAllTimers();
  });

  test("should render email confirm email template correctly", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const emailSpy = jest.spyOn(emailClient, "send");
    jest
      .spyOn(repoMock, "getUser")
      .mockReturnValueOnce(new Promise((resolve) => resolve(null)));
    await sut.register({ email: userData.email, password: userData.password });

    expect(emailSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        to: [userData.email],
        subject: "Confirm your email",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );
    expect(emailSpy.mock.calls[0][0].text).toMatch(
      /This is the confirm email template for email: \w+@email.com, link: http:\/\/mysite.com\/confirm-email\?token=\w+/,
    );
    expect(emailSpy.mock.calls[0][0].html).toMatch(
      /This is the confirm email template for email: \w+@email.com, <a href="http:\/\/mysite.com\/confirm-email\?token=\w+">link<\/a>/,
    );
  });

  test("should render email confirm reset password template correctly", async () => {
    const passauth = Passauth(passauthConfig);
    const sut = passauth.handler;

    const emailSpy = jest.spyOn(emailClient, "send");
    await sut.sendResetPasswordEmail(userData.email);

    expect(emailSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        to: [userData.email],
        subject: "Reset Password",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );
    expect(emailSpy.mock.calls[0][0].text).toMatch(
      /This is the reset password template for email: \w+@email.com, link: http:\/\/mysite.com\/reset-password\?token=\w+/,
    );
    expect(emailSpy.mock.calls[0][0].html).toMatch(
      /This is the reset password template for email: \w+@email.com, <a href="http:\/\/mysite.com\/reset-password\?token=\w+">link<\/a>/,
    );
  });
});

describe("Email:Options:emailConfig override", () => {
  const repoMock: AuthRepo<User> = {
    getUser: async (_email) => null,
    createUser: async (_params) => userData,
  };

  const passauthConfig = {
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

  test("Confirm Email - should override email params", async () => {
    const passauth = Passauth({
      ...passauthConfig,
      email: {
        ...emailConfig,
        emailConfig: {
          [TemplateTypes.CONFIRM_EMAIL]: {
            email: {
              from: "overridden@mysite.com",
              senderName: "Overridden Name",
              subject: "Overridden Subject - Confirm Email",
            },
            linkExpirationMs: 1000 * 60 * 15,
          },
        },
      },
    });
    const sut = passauth.handler;

    const emailSpy = jest.spyOn(emailClient, "send");
    await sut.register(userData);

    expect(emailSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        to: [userData.email],
        senderName: "Overridden Name",
        from: "overridden@mysite.com",
        subject: "Overridden Subject - Confirm Email",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );
  });

  test("Confirm Email - should allow overriding the link expiration time", async () => {
    const passauth = Passauth({
      ...passauthConfig,
      email: {
        ...emailConfig,
        emailConfig: {
          [TemplateTypes.CONFIRM_EMAIL]: {
            linkExpirationMs: 1000 * 60 * 15,
          },
        },
      },
    });
    const sut = passauth.handler;

    const createConfirmEmailLinkSpy = jest.spyOn(
      emailConfig.services,
      "createConfirmEmailLink",
    );
    await sut.register(userData);

    const token = createConfirmEmailLinkSpy.mock.calls[0][1];

    jest.advanceTimersByTime(1000 * 60 * 17);

    await expect(sut.confirmEmail(userData.email, token)).rejects.toThrow(
      PassauthInvalidConfirmEmailTokenException,
    );
  });

  test("Reset Password - should override email params", async () => {
    const passauth = Passauth({
      ...passauthConfig,
      email: {
        ...emailConfig,
        emailConfig: {
          [TemplateTypes.RESET_PASSWORD]: {
            email: {
              from: "overridden-reset@mysite.com",
              senderName: "Overridden Name - Reset",
              subject: "Overridden Subject - Reset Password",
            },
            linkExpirationMs: 1000 * 60 * 15,
          },
        },
      },
    });
    const sut = passauth.handler;

    const emailSpy = jest.spyOn(emailClient, "send");
    await sut.sendResetPasswordEmail(userData.email);

    expect(emailSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        to: [userData.email],
        senderName: "Overridden Name - Reset",
        from: "overridden-reset@mysite.com",
        subject: "Overridden Subject - Reset Password",
        text: expect.any(String),
        html: expect.any(String),
      }),
    );
  });

  test("Reset Password - should allow overriding the link expiration time", async () => {
    const passauth = Passauth({
      ...passauthConfig,
      email: {
        ...emailConfig,
        emailConfig: {
          [TemplateTypes.RESET_PASSWORD]: {
            linkExpirationMs: 1000 * 60 * 15,
          },
        },
      },
    });
    const sut = passauth.handler;

    const createResetPasswordLinkSpy = jest.spyOn(
      emailConfig.services,
      "createResetPasswordLink",
    );

    await sut.sendResetPasswordEmail(userData.email);

    const token = createResetPasswordLinkSpy.mock.calls[0][1];

    jest.advanceTimersByTime(1000 * 60 * 17);

    const isValid = await sut.confirmResetPassword(
      userData.email,
      token,
      "new-password",
    );

    expect(isValid).toEqual({ success: false });
  });
});
