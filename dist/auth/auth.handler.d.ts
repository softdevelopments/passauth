import type { AuthRepo, HandlerOptions, ID, LoginParams, PassauthHandler, RegisterParams, User } from "./auth.types.js";
export declare class AuthHandler<U extends User> implements PassauthHandler<U> {
    repo: AuthRepo<U>;
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
    constructor(options: HandlerOptions, repo: AuthRepo<U>);
    register(params: RegisterParams): Promise<U>;
    login(params: LoginParams, jwtUserFields?: Array<keyof U>): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    verifyAccessToken<D>(accessToken: string): import("./auth.utils.js").AuthJwtPayload<D>;
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
