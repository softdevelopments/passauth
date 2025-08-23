import { generateToken } from "./emai.utils";
import { DEFAULT_CONFIRMATION_LINK_EXPIRATION_MS, DEFAULT_RESET_PASSWORD_LINK_EXPIRATION_MS, } from "./email.constants";
import { PassauthEmailPluginMissingConfigurationException } from "./email.exceptions";
import { TemplateTypes, } from "./email.types";
export class EmailSender {
    constructor(options) {
        this.options = options;
        this.resetPasswordTokens = new Map();
        this.confirmEmailTokens = new Map();
        this.confirmationLinkExpiration = DEFAULT_CONFIRMATION_LINK_EXPIRATION_MS;
        this.resetPasswordLinkExpiration = DEFAULT_RESET_PASSWORD_LINK_EXPIRATION_MS;
        const confirmationExpiration = options.emailConfig?.[TemplateTypes.CONFIRM_EMAIL].linkExpirationMs;
        if (confirmationExpiration) {
            this.confirmationLinkExpiration = confirmationExpiration;
        }
        const resetPasswordExpiration = options.emailConfig?.[TemplateTypes.RESET_PASSWORD].linkExpirationMs;
        if (resetPasswordExpiration) {
            this.resetPasswordLinkExpiration = resetPasswordExpiration;
        }
    }
    getResetPasswordTemplate(args) {
        return {
            text: `Reset your password for email ${args.email} by clicking on the following link: ${args.link}`,
            html: `<p>Reset your password for email ${args.email} by clicking on the following link: <a href="${args.link}">${args.link}</a></p>`,
        };
    }
    getConfirmEmailTemplate(args) {
        return {
            text: `Confirm your email ${args.email} by clicking on the following link: ${args.link}`,
            html: `<p>Confirm your email ${args.email} by clicking on the following link: <a href="${args.link}">${args.link}</a></p>`,
        };
    }
    generateResetPasswordToken(email) {
        const token = generateToken();
        const exp = Date.now() + this.resetPasswordLinkExpiration;
        this.resetPasswordTokens.set(email, { token, exp });
        return token;
    }
    verifyToken(email, token, type) {
        const collection = type === TemplateTypes.RESET_PASSWORD
            ? this.resetPasswordTokens
            : this.confirmEmailTokens;
        const record = collection.get(email);
        if (!record) {
            return false;
        }
        if (record.token !== token) {
            return false;
        }
        if (Date.now() > record.exp) {
            this.resetPasswordTokens.delete(email);
            return false;
        }
        return true;
    }
    async sendResetPasswordEmail(email) {
        try {
            const { createResetPasswordLink } = this.options.services;
            const token = this.generateResetPasswordToken(email);
            const link = await createResetPasswordLink(email, token);
            const { text, html } = this.getResetPasswordTemplate({ email, link });
            const params = this.getEmailParams({
                to: [email],
                subject: "Reset Password",
                text,
                html,
            }, TemplateTypes.RESET_PASSWORD);
            await this.options.client.send(params);
            return { success: true };
        }
        catch (error) {
            return { success: false };
        }
    }
    async confirmEmail(email, token) {
        const isValid = this.verifyToken(email, token, TemplateTypes.CONFIRM_EMAIL);
        if (isValid) {
            this.confirmEmailTokens.delete(email);
            await this.options.repo.confirmEmail(email);
            return true;
        }
        return false;
    }
    async confirmResetPassword(email, token, password) {
        const isValid = this.verifyToken(email, token, TemplateTypes.RESET_PASSWORD);
        if (isValid) {
            this.resetPasswordTokens.delete(email);
            await this.options.repo.resetPassword(email, password);
            return true;
        }
        return false;
    }
    getEmailParams(emailArgs, templateType) {
        const overrideParams = this.options.emailConfig?.[templateType].email;
        return {
            senderName: overrideParams?.senderName || this.options.senderName,
            from: overrideParams?.from || this.options.senderEmail,
            to: emailArgs.to,
            subject: overrideParams?.subject || emailArgs.subject,
            text: emailArgs.text,
            html: emailArgs.html,
        };
    }
    generateConfirmPasswordToken(email) {
        const token = generateToken();
        const exp = Date.now() + this.confirmationLinkExpiration;
        this.confirmEmailTokens.set(email, { token, exp });
        return token;
    }
    async sendConfirmPasswordEmail(email) {
        try {
            const { createConfirmEmailLink } = this.options.services;
            const token = this.generateConfirmPasswordToken(email);
            const link = await createConfirmEmailLink(email, token);
            const { text, html } = this.getConfirmEmailTemplate({ email, link });
            const params = this.getEmailParams({
                to: [email],
                subject: "Confirm your email",
                text,
                html,
            }, TemplateTypes.CONFIRM_EMAIL);
            await this.options.client.send(params);
            return { success: true };
        }
        catch (error) {
            return { success: false };
        }
    }
}
export const EmailPlugin = (options) => {
    if (!options.senderName) {
        throw new PassauthEmailPluginMissingConfigurationException("senderName");
    }
    if (!options.senderEmail) {
        throw new PassauthEmailPluginMissingConfigurationException("senderEmail");
    }
    if (!options.client) {
        throw new PassauthEmailPluginMissingConfigurationException("client");
    }
    if (!options.services) {
        throw new PassauthEmailPluginMissingConfigurationException("services");
    }
    const emailSender = new EmailSender(options);
    return emailSender;
};
//# sourceMappingURL=email.handler.js.map