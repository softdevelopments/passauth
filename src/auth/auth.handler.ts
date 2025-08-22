import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import {
  EmailSenderRequiredException,
  InvalidCredentialsException,
  InvalidRefreshTokenException,
  InvalidUserException,
  PassauthEmailAlreadyTakenException,
} from "./auth.exceptions";
import {
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_ROUNDS,
} from "./auth.constants";
import type {
  AuthRepo,
  HandlerOptions,
  ID,
  LoginParams,
  RegisterParams,
  User,
} from "./auth.types";
import type { EmailSender } from "../email/email.handler";
import {
  decodeAccessToken,
  generateAccessToken,
  generateRefreshToken,
  hash,
} from "./auth.utils";

export class AuthHandler<T extends User> {
  private refreshTokensLocalChaching: {
    [userId: ID]: {
      token: string;
      exp: number;
    };
  } = {};

  constructor(
    private options: HandlerOptions,
    private repo: AuthRepo<T>,
    private emailSender?: EmailSender
  ) {
    this.options.saltingRounds = options.saltingRounds || DEFAULT_ROUNDS;
    this.options.accessTokenExpirationMs =
      options.accessTokenExpirationMs || DEFAULT_JWT_EXPIRATION_MS;
    this.options.refreshTokenExpirationMs =
      options.refreshTokenExpirationMs || DEFAULT_REFRESH_EXPIRATION_TOKEN_MS;
  }

  async register(params: RegisterParams) {
    const existingUser = await this.repo.getUser(params.email);

    if (existingUser) {
      throw new PassauthEmailAlreadyTakenException();
    }

    const createdUser = await this.repo.createUser({
      ...params,
      password: await hash(params.password, this.options.saltingRounds),
    });

    if (this.options.requireEmailConfirmation) {
      await this.emailSender?.sendConfirmPasswordEmail(createdUser.email);
    }
  }

  async login(params: LoginParams) {
    const user = await this.repo.getUser(params.email);

    if (!user) {
      throw new InvalidUserException(params.email);
    }

    const isValidPassword = await this.comparePasswords(
      params.password,
      user.password
    );

    if (!isValidPassword) {
      throw new InvalidCredentialsException();
    }

    const tokens = this.generateTokens(user.id);

    return tokens;
  }

  private async validateRefreshToken(userId: ID, refreshToken: string) {
    const cachedToken = this.refreshTokensLocalChaching[userId];

    if (!cachedToken || !cachedToken.token) {
      throw new InvalidRefreshTokenException();
    }

    const hashedToken = await this.hashRefreshToken(refreshToken, userId);

    const isValid = hashedToken === cachedToken.token;

    if (!isValid) {
      throw new InvalidRefreshTokenException();
    }

    const now = Date.now();

    if (now >= cachedToken.exp) {
      throw new InvalidRefreshTokenException();
    }
  }

  async refreshToken(accessToken: string, refreshToken: string) {
    const { sub } = decodeAccessToken(accessToken);

    await this.validateRefreshToken(sub!, refreshToken);

    const tokens = this.generateTokens(sub);

    return tokens;
  }

  revokeRefreshToken(userId: ID) {
    delete this.refreshTokensLocalChaching[userId];
  }

  private async saveRefreshToken(
    userId: ID,
    refreshToken: string,
    exp: number
  ) {
    this.refreshTokensLocalChaching[userId] = {
      token: await this.hashRefreshToken(refreshToken, userId),
      exp,
    };
  }

  private hashRefreshToken(token: string, userId: ID) {
    return hash(`${userId}${token}`, 2);
  }

  async resetPassword(email: string) {
    if (!this.emailSender) {
      throw new EmailSenderRequiredException();
    }

    const success = await this.emailSender.sendResetPasswordEmail(email);
  }

  private generateTokens(userId: ID) {
    const accessToken = generateAccessToken({
      userId,
      secretKey: this.options.secretKey,
      expiresIn: this.options.accessTokenExpirationMs,
    });
    const { token: refreshToken, exp } = generateRefreshToken({
      expiresIn: this.options.refreshTokenExpirationMs,
    });

    this.saveRefreshToken(userId, refreshToken, exp);

    return { accessToken, refreshToken };
  }

  private async comparePasswords(password: string, hash: string) {
    const isValid = await bcrypt.compare(password, hash);

    return isValid;
  }
}
