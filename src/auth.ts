import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { v4 as uuid } from "uuid";

import {
  InvalidCredentialsException,
  InvalidRefreshTokenException,
  InvalidUserException,
  PassauthEmailAlreadyTakenException,
} from "./exceptions";
import {
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_ROUNDS,
} from "./constants";
import type {
  AuthRepo,
  HandlerOptions,
  ID,
  LoginParams,
  RegisterParams,
  TokenPayload,
  User,
} from "./types";

export class AuthHandler<T extends User> {
  constructor(private options: HandlerOptions, private repo: AuthRepo<T>) {
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

    return this.repo.createUser({
      ...params,
      password: await this.hashPassword(params.password),
    });
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

    const tokens = await this.generateTokens(user.id);

    return tokens;
  }

  async refreshToken(token: string) {
    const {
      data: { id },
    } = this.decodeRefreshToken(token);

    const savedRefreshToken = await this.repo.getRefreshToken(id);

    if (!savedRefreshToken) {
      throw new InvalidRefreshTokenException();
    }

    const tokens = await this.generateTokens(id);

    return tokens;
  }

  async revokeRefreshToken(userId: ID) {
    await this.repo.invalidateRefreshToken(userId);
  }

  private async generateTokens(userId: ID) {
    const accessToken = this.generateAccessToken(userId);
    const refreshToken = this.generateRefreshToken(userId);

    await this.repo.invalidateRefreshToken(userId);
    await this.repo.saveRefreshToken(userId, refreshToken);

    return { accessToken, refreshToken };
  }

  private generateAccessToken(userId: ID) {
    return jwt.sign(
      { data: { id: userId, tokenId: uuid() } },
      this.options.secretKey,
      {
        expiresIn: this.options.accessTokenExpirationMs,
      }
    );
  }

  private generateRefreshToken(userId: ID) {
    return jwt.sign(
      { data: { id: userId, tokenId: uuid() } },
      this.options.secretKey,
      {
        expiresIn: this.options.refreshTokenExpirationMs,
      }
    );
  }

  private decodeRefreshToken(token: string) {
    try {
      const decoded = jwt.verify(
        token,
        this.options.secretKey
      ) as jwt.JwtPayload & TokenPayload;
      return decoded;
    } catch (error) {
      throw new InvalidRefreshTokenException();
    }
  }

  private async hashPassword(password: string) {
    const salt = await bcrypt.genSalt(this.options.saltingRounds);

    return bcrypt.hash(password, salt);
  }

  private async comparePasswords(password: string, hash: string) {
    const isValid = await bcrypt.compare(password, hash);

    return isValid;
  }
}
