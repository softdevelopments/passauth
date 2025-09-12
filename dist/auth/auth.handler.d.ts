import type { AuthRepo, HandlerOptions, ID, LoginParams, RegisterParams, User } from "./auth.types.js";
export declare class AuthHandler<T extends User> {
    repo: AuthRepo<T>;
    private refreshTokensLocalChaching;
    private config;
    constructor(options: HandlerOptions, repo: AuthRepo<T>);
    register(params: RegisterParams): Promise<T>;
    login(params: LoginParams): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    verifyAccessToken(accessToken: string): import("jsonwebtoken").JwtPayload;
    refreshToken(accessToken: string, refreshToken: string): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    revokeRefreshToken(userId: ID): void;
    private validateRefreshToken;
    private saveRefreshToken;
    private hashRefreshToken;
    private compareRefeshToken;
    generateTokens(userId: ID): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
}
