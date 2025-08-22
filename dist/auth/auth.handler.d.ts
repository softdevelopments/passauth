import type { AuthRepo, HandlerOptions, ID, LoginParams, RegisterParams, User } from "./auth.types";
import type { EmailSender } from "../email/email.handler";
export declare class AuthHandler<T extends User> {
    private repo;
    private emailSender?;
    private refreshTokensLocalChaching;
    private config;
    constructor(options: HandlerOptions, repo: AuthRepo<T>, emailSender?: EmailSender | undefined);
    register(params: RegisterParams): Promise<T>;
    login(params: LoginParams): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    verifyAccessToken(accessToken: string): import("jsonwebtoken").JwtPayload;
    private validateRefreshToken;
    refreshToken(accessToken: string, refreshToken: string): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
    revokeRefreshToken(userId: ID): void;
    private saveRefreshToken;
    private hashRefreshToken;
    resetPassword(email: string): Promise<void>;
    private generateTokens;
    private comparePasswords;
}
//# sourceMappingURL=auth.handler.d.ts.map