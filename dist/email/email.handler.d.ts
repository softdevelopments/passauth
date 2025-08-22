import { type EmailPluginOptions } from "./email.types";
export declare class EmailSender {
    private options;
    private resetPasswordTokens;
    private confirmEmailTokens;
    private confirmationLinkExpiration;
    private resetPasswordLinkExpiration;
    constructor(options: EmailPluginOptions);
    private getResetPasswordTemplate;
    private getConfirmEmailTemplate;
    private generateResetPasswordToken;
    private verifyToken;
    sendResetPasswordEmail(email: string): Promise<{
        success: boolean;
    }>;
    confirmEmail(email: string, token: string): Promise<boolean>;
    confirmResetPassword(email: string, token: string, password: string): Promise<boolean>;
    private getEmailParams;
    private generateConfirmPasswordToken;
    sendConfirmPasswordEmail(email: string): Promise<{
        success: boolean;
    }>;
}
export declare const EmailPlugin: (options: EmailPluginOptions) => EmailSender;
//# sourceMappingURL=email.handler.d.ts.map