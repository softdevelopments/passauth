import type { AuthRepo, HandlerOptions, ID, LoginParams, RegisterParams, User } from "./auth.types";
import type { EmailSender } from "../email/email.handler";
export declare class AuthHandler<T extends User> {
    private options;
    private repo;
    private emailSender?;
    private refreshTokensLocalChaching;
    constructor(options: HandlerOptions, repo: AuthRepo<T>, emailSender?: EmailSender | undefined);
    register(params: RegisterParams): Promise<void>;
    login(params: LoginParams): Promise<{
        accessToken: string;
        refreshToken: string;
    }>;
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