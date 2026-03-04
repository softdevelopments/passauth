import type { AuthRepo, HandlerOptions, ID, LoginParams, PassauthHandler, RegisterParams, User } from "../interfaces/index.js";
export declare class AuthHandler<U extends User> implements PassauthHandler<U> {
    private options;
    repo: AuthRepo<U>;
    private emailHandler;
    private refreshTokensLocalChaching;
    private config;
    _aux: {
        config: {
            SALTING_ROUNDS: number;
            ACCESS_TOKEN_EXPIRATION_MS: number;
            REFRESH_TOKEN_EXPIRATION_MS: number;
            SECRET_KEY: string;
        };
        validateRefreshToken: "string" | "number" | "bigint" | "boolean" | "symbol" | "undefined" | "object" | "function";
        saveRefreshToken: "string" | "number" | "bigint" | "boolean" | "symbol" | "undefined" | "object" | "function";
        hashRefreshToken: "string" | "number" | "bigint" | "boolean" | "symbol" | "undefined" | "object" | "function";
        compareRefeshToken: "string" | "number" | "bigint" | "boolean" | "symbol" | "undefined" | "object" | "function";
    };
    _name: string;
    constructor(options: HandlerOptions, repo: AuthRepo<U>);
    register<T>(params: RegisterParams<T>): Promise<U>;
    sendResetPasswordEmail(email: string): Promise<{
        success: boolean;
        error: unknown;
    } | {
        success: boolean;
    }>;
    sendConfirmPasswordEmail(email: string): Promise<{
        success: boolean;
    }>;
    confirmEmail(email: string, token: string): Promise<void>;
    confirmResetPassword(email: string, token: string, password: string): Promise<{
        success: boolean;
        error: unknown;
    } | {
        success: boolean;
    }>;
    login<T>(params: LoginParams<T>, config?: {
        jwtUserFields?: Array<keyof U>;
    }): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    verifyAccessToken<D>(accessToken: string): import("../index.js").AuthJwtPayload<D>;
    refreshToken(accessToken: string, refreshToken: string): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    revokeRefreshToken(userId: ID): Promise<void>;
    generateTokens<D>(userId: ID, data?: D): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    private getCachedRefreshToken;
    private validateRefreshToken;
    private saveRefreshToken;
    private hashRefreshToken;
    private compareRefeshToken;
}
