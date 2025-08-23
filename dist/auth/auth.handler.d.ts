import type { AuthRepo, HandlerOptions, ID, LoginParams, RegisterParams, User } from "./auth.types";
import type { EmailSender } from "../email/email.handler";
export declare class AuthHandler<T extends User> {
    private repo;
    private emailSender?;
    private refreshTokensLocalChaching;
    private config;
    constructor(options: HandlerOptions, repo: AuthRepo<T>, emailSender?: EmailSender | undefined);
    register(params: RegisterParams): Promise<{
        user: T;
        emailSent: boolean;
    }>;
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
    resetPassword(email: string): Promise<{
        success: boolean;
    }>;
    private generateTokens;
}
//# sourceMappingURL=auth.handler.d.ts.map