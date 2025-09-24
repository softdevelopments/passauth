/* eslint-disable @typescript-eslint/no-explicit-any */
import {
  describe,
  test,
  expect,
  beforeEach,
  jest,
  beforeAll,
} from "@jest/globals";
import { Passauth, SharedComponents } from "../../src";
import {
  LoginParams,
  PassauthConfiguration,
  User,
} from "../../src/auth/auth.types.js";

import { AuthRepo } from "../../src/auth/auth.types.js";
import { hash } from "../../src/auth/auth.utils.js";
import { DEFAULT_SALTING_ROUNDS } from "../../src/auth/auth.constants.js";

const userData = {
  id: 1,
  email: "user@email.com",
  password: "password123",
  emailVerified: false,
  isBlocked: false,
};

describe("Plugin", () => {
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

  test("Should be able to override Passauth handler methods", async () => {
    const customPlugin = (config: { loginText: string }) => {
      return {
        name: "CustomPlugin",
        handlerInit: ({ passauthHandler }: SharedComponents<User>) => {
          passauthHandler.login = async (_params: LoginParams) => {
            return {
              loginText: config.loginText,
              accessToken: "ACCESS_TOKEN",
              refreshToken: "REFRESH_TOKEN",
            };
          };
        },
      };
    };

    const passauth = Passauth({
      ...passauthConfig,
      plugins: [
        customPlugin({
          loginText: "Testing",
        }),
      ],
    });

    const result = await passauth.handler.login({
      email: userData.email,
      password: userData.password,
    });

    expect(result).toEqual({
      loginText: "Testing",
      accessToken: "ACCESS_TOKEN",
      refreshToken: "REFRESH_TOKEN",
    });
  });

  test("Should be able to extend Passauth handler methods", async () => {
    const customPlugin = (config: { passwordRegex: RegExp }) => {
      return {
        name: "CustomPlugin",
        handlerInit: ({ passauthHandler }: SharedComponents<User>) => {
          const login = passauthHandler.login.bind(passauthHandler);

          passauthHandler.login = async (params: LoginParams) => {
            if (!params.password.match(config.passwordRegex)) {
              throw new Error("Invalid password");
            }

            return login(params);
          };
        },
      };
    };

    const passauth = Passauth({
      ...passauthConfig,
      plugins: [
        customPlugin({
          passwordRegex: /\d{4}[a-zA-Z]{4}/,
        }),
      ],
    });

    await expect(
      passauth.handler.login({
        email: userData.email,
        password: userData.password,
      })
    ).rejects.toThrow("Invalid password");

    jest.spyOn(repoMock, "getUser").mockImplementationOnce(async (_email) => ({
      ...userData,
      password: await hash("1234pass", DEFAULT_SALTING_ROUNDS),
    }));

    expect(
      await passauth.handler.login({
        email: userData.email,
        password: "1234pass",
      })
    ).toEqual(
      expect.objectContaining({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
      })
    );
  });

  test("Should be able to access config Passauth handler methods", async () => {
    const customPlugin = (config: { passwordRegex: RegExp }) => {
      return {
        name: "CustomPlugin",
        handlerInit: ({ passauthHandler }: SharedComponents<User>) => {
          (passauthHandler as any).getConfig = () => {
            return {
              saltingRounds: passauth.handler._aux.config.SALTING_ROUNDS,
            };
          };
        },
      };
    };

    const passauth = Passauth({
      ...passauthConfig,
      plugins: [
        customPlugin({
          passwordRegex: /\d{4}[a-zA-Z]{4}/,
        }),
      ],
    });

    expect((passauth.handler as any).getConfig()).toEqual({
      saltingRounds: DEFAULT_SALTING_ROUNDS,
    });
  });
});
