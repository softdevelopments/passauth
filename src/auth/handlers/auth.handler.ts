import {
  PassauthInvalidCredentialsException,
  PassauthInvalidRefreshTokenException,
  PassauthInvalidUserException,
  PassauthEmailAlreadyTakenException,
  PassauthInvalidAccessTokenException,
  PassauthBlockedUserException,
  PassauthExceptionContext,
} from "../exceptions/auth.exceptions";
import {
  PassauthEmailFailedToSendEmailException,
  PassauthEmailNotVerifiedException,
} from "../exceptions/email.exceptions";
import {
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_SALTING_ROUNDS,
} from "../constants/auth.constants";
import type {
  AuthRepo,
  ConfirmEmailParams,
  HandlerOptions,
  ID,
  LoginParams,
  PassauthHandler,
  RegisterParams,
  ResetPasswordEmailParams,
  User,
} from "../interfaces";
import {
  decodeAccessToken,
  verifyAccessToken,
  generateAccessToken,
  generateRefreshToken,
  hash,
  compareHash,
} from "../utils/auth.utils";
import { EmailHandler } from "./email.handler";

export class AuthHandler<U extends User> implements PassauthHandler<U> {
  private emailHandler: EmailHandler | undefined;

  private refreshTokensLocalChaching: {
    [userId: ID]: {
      token: string;
      exp: number;
    };
  } = {};
  private config: {
    SALTING_ROUNDS: number;
    ACCESS_TOKEN_EXPIRATION_MS: number;
    REFRESH_TOKEN_EXPIRATION_MS: number;
    SECRET_KEY: string;
  };

  public _aux;
  public _name = "Passauth";

  constructor(
    private options: HandlerOptions,
    public repo: AuthRepo<U>,
  ) {
    this.config = {
      SALTING_ROUNDS: options.saltingRounds || DEFAULT_SALTING_ROUNDS,
      ACCESS_TOKEN_EXPIRATION_MS:
        options.accessTokenExpirationMs || DEFAULT_JWT_EXPIRATION_MS,
      REFRESH_TOKEN_EXPIRATION_MS:
        options.refreshTokenExpirationMs || DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
      SECRET_KEY: options.secretKey,
    };

    this._aux = {
      config: this.config,
      validateRefreshToken: typeof this.validateRefreshToken,
      saveRefreshToken: typeof this.saveRefreshToken,
      hashRefreshToken: typeof this.hashRefreshToken,
      compareRefeshToken: typeof this.compareRefeshToken,
    };

    if (options.email) {
      this.emailHandler = new EmailHandler(options.email, {
        saltingRounds: this.config.SALTING_ROUNDS,
      });
    }
  }

  async register<T>(params: RegisterParams<T>) {
    const existingUser = await this.repo.getUser({
      email: params.email,
    } as Partial<U>);

    if (existingUser) {
      throw new PassauthEmailAlreadyTakenException();
    }

    const createdUser = await this.repo.createUser({
      ...params,
      password: await hash(params.password, this.config.SALTING_ROUNDS),
    });

    if (params.email && this.emailHandler) {
      const { success } = await this.emailHandler.sendConfirmPasswordEmail(
        createdUser.email,
      );

      if (!success) {
        throw new PassauthEmailFailedToSendEmailException(
          PassauthExceptionContext.REGISTER,
          params.email,
        );
      }
    }

    return createdUser;
  }

  async sendResetPasswordEmail(
    email: string,
    emailParams?: ResetPasswordEmailParams,
  ) {
    if (!this.emailHandler) {
      return { success: false };
    }

    return this.emailHandler.sendResetPasswordEmail(email, emailParams);
  }

  async sendConfirmPasswordEmail(email: string, emailParams?: ConfirmEmailParams) {
    if (!this.emailHandler) {
      return { success: false };
    }

    return this.emailHandler.sendConfirmPasswordEmail(email, emailParams);
  }

  async confirmEmail(email: string, token: string, emailParams?: ConfirmEmailParams) {
    if (!this.emailHandler) {
      throw new Error("Email handler not configured");
    }

    return this.emailHandler.confirmEmail(email, token, emailParams);
  }

  async confirmResetPassword(
    email: string,
    token: string,
    password: string,
    emailParams?: ResetPasswordEmailParams,
  ) {
    if (!this.emailHandler) {
      return { success: false };
    }

    return this.emailHandler.confirmResetPassword(
      email,
      token,
      password,
      emailParams,
    );
  }

  async login<T>(
    params: LoginParams<T>,
    config?: { jwtUserFields?: Array<keyof U> },
  ) {
    const user = await this.repo.getUser(params as Partial<U>);

    if (!user) {
      throw new PassauthInvalidUserException(params.email);
    }

    if (user.isBlocked) {
      throw new PassauthBlockedUserException(params.email);
    }

    if (this.emailHandler && !user.emailVerified) {
      throw new PassauthEmailNotVerifiedException(params.email);
    }

    const isValidPassword = await compareHash(params.password, user.password);

    if (!isValidPassword) {
      throw new PassauthInvalidCredentialsException();
    }

    const jwtData = config?.jwtUserFields
      ? config.jwtUserFields.reduce((params, userKey) => {
          params[userKey] = user[userKey];

          return params;
        }, {} as Partial<U>)
      : undefined;

    const tokens = this.generateTokens(user.id, jwtData);

    return tokens;
  }

  verifyAccessToken<D>(accessToken: string) {
    const decodedToken = verifyAccessToken<D>(
      accessToken,
      this.config.SECRET_KEY,
    );

    if (!decodedToken) {
      throw new PassauthInvalidAccessTokenException();
    }

    return decodedToken;
  }

  async refreshToken(accessToken: string, refreshToken: string) {
    const { sub, data } = decodeAccessToken(accessToken);

    await this.validateRefreshToken(sub!, refreshToken);

    const tokens = await this.generateTokens(sub, data);

    return tokens;
  }

  async revokeRefreshToken(userId: ID) {
    if (this.repo.deleteCachedToken) {
      await this.repo.deleteCachedToken(userId);
    } else {
      delete this.refreshTokensLocalChaching[userId];
    }
  }

  async generateTokens<D>(userId: ID, data?: D) {
    const accessToken = generateAccessToken({
      userId,
      secretKey: this.config.SECRET_KEY,
      expiresIn: this.config.ACCESS_TOKEN_EXPIRATION_MS,
      data,
    });
    const { token: refreshToken, exp } = generateRefreshToken({
      expiresIn: this.config.REFRESH_TOKEN_EXPIRATION_MS,
    });

    await this.saveRefreshToken(userId, refreshToken, exp);

    return { accessToken, refreshToken };
  }

  private async getCachedRefreshToken(userId: ID) {
    if (this.repo.getCachedToken) {
      const cachedToken = await this.repo.getCachedToken(userId);

      return cachedToken;
    }

    const cachedToken = this.refreshTokensLocalChaching[userId];

    const now = Date.now();

    if (!cachedToken) {
      return null;
    }

    if (now >= cachedToken.exp) {
      return null;
    }

    return cachedToken.token;
  }

  private async validateRefreshToken(userId: ID, refreshToken: string) {
    const cachedToken = await this.getCachedRefreshToken(userId);

    if (!cachedToken) {
      throw new PassauthInvalidRefreshTokenException();
    }

    const isValid = await this.compareRefeshToken(
      refreshToken,
      userId,
      cachedToken,
    );

    if (!isValid) {
      throw new PassauthInvalidRefreshTokenException();
    }
  }

  private async saveRefreshToken(
    userId: ID,
    refreshToken: string,
    exp: number,
  ) {
    const hashedToken = await this.hashRefreshToken(refreshToken, userId);

    const tokenData = {
      token: hashedToken,
      exp,
    };

    if (this.repo.saveCachedToken) {
      await this.repo.saveCachedToken(
        userId,
        tokenData.token,
        this.config.REFRESH_TOKEN_EXPIRATION_MS,
      );
    } else {
      this.refreshTokensLocalChaching[userId] = tokenData;
    }
  }

  private async hashRefreshToken(token: string, userId: ID) {
    const hashed = await hash(`${userId}${token}`, 2);

    return hashed;
  }

  private async compareRefeshToken(
    token: string,
    userId: ID,
    hashedToken: string,
  ) {
    const isValid = await compareHash(`${userId}${token}`, hashedToken);

    return isValid;
  }
}
