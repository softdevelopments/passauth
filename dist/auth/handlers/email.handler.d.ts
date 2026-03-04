import { EmailHandlerOptions } from "../interfaces/email.types.js";
export declare class EmailHandler {
    private options;
    private config;
    private saltingRounds;
    private resetPasswordTokens;
    private confirmEmailTokens;
    private confirmationLinkExpiration;
    private resetPasswordLinkExpiration;
    constructor(options: EmailHandlerOptions, config: {
        saltingRounds: number;
    });
    confirmResetPassword(email: string, token: string, password: string): Promise<{
        success: boolean;
        error?: never;
    } | {
        success: boolean;
        error: unknown;
    }>;
    private verifyToken;
    sendConfirmPasswordEmail(email: string): Promise<{
        success: boolean;
    }>;
    confirmEmail(email: string, token: string): Promise<void>;
    sendResetPasswordEmail(email: string): Promise<{
        success: boolean;
        error?: never;
    } | {
        success: boolean;
        error: unknown;
    }>;
    private generateResetPasswordToken;
    private getResetPasswordTemplate;
    private getConfirmEmailTemplate;
    private getEmailParams;
    private generateConfirmPasswordToken;
}
