import { AuthJwtPayload } from "./auth.utils";

export type ID = string | number;

export type User = {
  id: ID;
  email: string;
  password: string;
  isBlocked: boolean;
};

export type RegisterParams = {
  email: string;
  password: string;
};

export type LoginParams = {
  email: string;
  password: string;
};

export interface AuthRepo<T extends User> {
  getUser(param: Partial<T>): Promise<T | null>;
  createUser(params: RegisterParams): Promise<T>;
  getCachedToken?: (userId: ID) => Promise<string | undefined | null>;
  saveCachedToken?: (
    userId: ID,
    token: string,
    expiresInMs: number,
  ) => Promise<void>;
  deleteCachedToken?: (userId: ID) => Promise<void>;
}

export type HandlerOptions = {
  secretKey: string;
  saltingRounds?: number;
  accessTokenExpirationMs?: number;
  refreshTokenExpirationMs?: number;
};

export type PassauthConfiguration<U extends User, P> = HandlerOptions & {
  repo: AuthRepo<U>;
  plugins?: P;
};

type AuthTokensResponse = {
  accessToken: string;
  refreshToken: string;
};

export interface PassauthHandler<U extends User> {
  repo: AuthRepo<U>;
  register(params: RegisterParams): Promise<U>;
  login(
    params: LoginParams,
    jwtUserFields?: Array<keyof U>,
  ): Promise<AuthTokensResponse>;
  verifyAccessToken<D>(accessToken: string): AuthJwtPayload<D>;
  refreshToken(
    accessToken: string,
    refreshToken: string,
  ): Promise<AuthTokensResponse>;
  revokeRefreshToken(userId: ID): Promise<void>;
  generateTokens<D>(userId: ID, data?: D): Promise<AuthTokensResponse>;
}

export type PassauthHandlerConfig = {
  SALTING_ROUNDS: number;
  ACCESS_TOKEN_EXPIRATION_MS: number;
  REFRESH_TOKEN_EXPIRATION_MS: number;
  SECRET_KEY: string;
};

type PassauthHandlerPrivate = {
  validateRefreshToken(userId: ID, refreshToken: string): Promise<void>;
  saveRefreshToken(
    userId: ID,
    refreshToken: string,
    exp: number,
  ): Promise<void>;
  hashRefreshToken(token: string, userId: ID): Promise<string>;
  compareRefeshToken(
    token: string,
    userId: ID,
    hashedToken: string,
  ): Promise<boolean>;
};

export interface PassauthHandlerInt<U extends User> extends PassauthHandler<U> {
  _name: string;
  _aux: {
    config: PassauthHandlerConfig;
  } & PassauthHandlerPrivate;
}
