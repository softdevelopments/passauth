import { AuthJwtPayload } from "../utils/auth.utils";
import {
  ConfirmEmailParams,
  EmailHandlerOptions,
  ResetPasswordEmailParams,
} from "../interfaces/email.types";
import type {
  LoginAttemptState,
  NormalizedPasswordPolicy,
  PasswordPolicyContext,
  PasswordPolicyOptions,
  PasswordValidationResult,
} from "./password.types";

export type ID = string | number;

export type User = {
  id: ID;
  email: string;
  password: string;
  isBlocked: boolean;
  emailVerified: boolean;
};

export type RegisterParams<P = Record<string, never>> = {
  email: string;
  password: string;
} & P;

export type LoginParams<P = Record<string, never>> = {
  email: string;
  password: string;
} & P;

export interface AuthRepo<T extends User> {
  getUser(param: Partial<T>): Promise<T | null>;
  createUser<P>(params: RegisterParams<P>): Promise<T>;
  getCachedToken?: (userId: ID) => Promise<string | undefined | null>;
  saveCachedToken?: (
    userId: ID,
    token: string,
    expiresInMs: number,
  ) => Promise<void>;
  deleteCachedToken?: (userId: ID) => Promise<void>;
}

export type HandlerOptions<
  PasswordParams extends Record<string, unknown> = Record<string, never>,
> = {
  secretKey: string;
  saltingRounds?: number;
  accessTokenExpirationMs?: number;
  refreshTokenExpirationMs?: number;
  email?: EmailHandlerOptions;
  passwordPolicy?: PasswordPolicyOptions<PasswordParams>;
};

export type PassauthConfiguration<
  U extends User,
  P = undefined,
  PasswordParams extends Record<string, unknown> = Record<string, never>,
> = HandlerOptions<PasswordParams> & {
  repo: AuthRepo<U>;
  plugins?: P;
};

type AuthTokensResponse = {
  accessToken: string;
  refreshToken: string;
};

export interface PassauthHandler<U extends User> {
  repo: AuthRepo<U>;
  register<T>(params: RegisterParams<T>): Promise<U>;
  login<T>(
    params: LoginParams<T>,
    config?: { jwtUserFields?: Array<keyof U> },
  ): Promise<AuthTokensResponse>;
  verifyAccessToken<D>(accessToken: string): AuthJwtPayload<D>;
  refreshToken(
    accessToken: string,
    refreshToken: string,
  ): Promise<AuthTokensResponse>;
  revokeRefreshToken(userId: ID): Promise<void>;
  generateTokens<D>(userId: ID, data?: D): Promise<AuthTokensResponse>;
  validatePassword<P extends Record<string, unknown> = Record<string, never>>(
    password: string,
    context?: PasswordPolicyContext<P>,
  ): PasswordValidationResult;
  assertPasswordPolicy<P extends Record<string, unknown> = Record<string, never>>(
    password: string,
    context?: PasswordPolicyContext<P>,
  ): void;
  getPasswordPolicy<P extends Record<string, unknown> = Record<string, never>>(
    context?: PasswordPolicyContext<P>,
  ): NormalizedPasswordPolicy;
  getLoginAttemptState<
    P extends Record<string, unknown> = Record<string, never>,
  >(
    email: string,
    context?: PasswordPolicyContext<P>,
  ): Promise<LoginAttemptState>;
  resetLoginAttempts<P extends Record<string, unknown> = Record<string, never>>(
    email: string,
    context?: PasswordPolicyContext<P>,
  ): Promise<void>;
  sendResetPasswordEmail(
    email: string,
    emailParams?: ResetPasswordEmailParams,
  ): Promise<{ success: boolean; error?: unknown }>;
  confirmResetPassword(
    email: string,
    token: string,
    password: string,
    emailParams?: ResetPasswordEmailParams,
  ): Promise<{ success: boolean; error?: unknown }>;
  confirmEmail(
    email: string,
    token: string,
    emailParams?: ConfirmEmailParams,
  ): Promise<void>;
  sendConfirmPasswordEmail(
    email: string,
    emailParams?: ConfirmEmailParams,
  ): Promise<{ success: boolean; error?: unknown }>;
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
