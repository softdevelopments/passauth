import jwt from "jsonwebtoken";
import {
  PassauthInvalidCredentialsException,
  PassauthInvalidRefreshTokenException,
  PassauthInvalidUserException,
  PassauthEmailAlreadyTakenException,
  PassauthInvalidAccessTokenException,
} from "./auth.exceptions";
import {
  DEFAULT_JWT_EXPIRATION_MS,
  DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
  DEFAULT_SALTING_ROUNDS,
} from "./auth.constants";
import type {
  AuthRepo,
  HandlerOptions,
  ID,
  LoginParams,
  RegisterParams,
  User,
} from "./auth.types";
import {
  decodeAccessToken,
  verifyAccessToken,
  generateAccessToken,
  generateRefreshToken,
  hash,
  compareHash,
} from "./auth.utils";

export class AuthHandler<T extends User> {
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

  constructor(options: HandlerOptions, public repo: AuthRepo<T>) {
    this.config = {
      SALTING_ROUNDS: options.saltingRounds || DEFAULT_SALTING_ROUNDS,
      ACCESS_TOKEN_EXPIRATION_MS:
        options.accessTokenExpirationMs || DEFAULT_JWT_EXPIRATION_MS,
      REFRESH_TOKEN_EXPIRATION_MS:
        options.refreshTokenExpirationMs || DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
      SECRET_KEY: options.secretKey,
    };
  }

  async register(params: RegisterParams) {
    const existingUser = await this.repo.getUser({
      email: params.email,
    } as Partial<T>);

    if (existingUser) {
      throw new PassauthEmailAlreadyTakenException();
    }

    const createdUser = await this.repo.createUser({
      ...params,
      password: await hash(params.password, this.config.SALTING_ROUNDS),
    });

    return createdUser;
  }

  async login(params: LoginParams) {
    const user = await this.repo.getUser({ email: params.email } as Partial<T>);

    if (!user) {
      throw new PassauthInvalidUserException(params.email);
    }

    const isValidPassword = await compareHash(params.password, user.password);

    if (!isValidPassword) {
      throw new PassauthInvalidCredentialsException();
    }

    const tokens = this.generateTokens(user.id);

    return tokens;
  }

  verifyAccessToken<D>(
    accessToken: string
  ): jwt.JwtPayload & { data: D | undefined } {
    const decodedToken = verifyAccessToken<D>(
      accessToken,
      this.config.SECRET_KEY
    );

    if (!decodedToken) {
      throw new PassauthInvalidAccessTokenException();
    }

    return decodedToken;
  }

  async refreshToken(accessToken: string, refreshToken: string) {
    const { sub } = decodeAccessToken(accessToken);

    await this.validateRefreshToken(sub!, refreshToken);

    const tokens = await this.generateTokens(sub);

    return tokens;
  }

  revokeRefreshToken(userId: ID) {
    delete this.refreshTokensLocalChaching[userId];
  }

  private async validateRefreshToken(userId: ID, refreshToken: string) {
    const cachedToken = this.refreshTokensLocalChaching[userId];

    if (!cachedToken || !cachedToken.token) {
      throw new PassauthInvalidRefreshTokenException();
    }

    const isValid = await this.compareRefeshToken(
      refreshToken,
      userId,
      cachedToken.token
    );

    if (!isValid) {
      throw new PassauthInvalidRefreshTokenException();
    }

    const now = Date.now();

    if (now >= cachedToken.exp) {
      throw new PassauthInvalidRefreshTokenException();
    }
  }

  private async saveRefreshToken(
    userId: ID,
    refreshToken: string,
    exp: number
  ) {
    const hashedToken = await this.hashRefreshToken(refreshToken, userId);

    const tokenData = {
      token: hashedToken,
      exp,
    };

    this.refreshTokensLocalChaching[userId] = tokenData;
  }

  private async hashRefreshToken(token: string, userId: ID) {
    const hashed = await hash(`${userId}${token}`, 2);

    return hashed;
  }

  private async compareRefeshToken(
    token: string,
    userId: ID,
    hashedToken: string
  ) {
    const isValid = await compareHash(`${userId}${token}`, hashedToken);

    return isValid;
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
}
