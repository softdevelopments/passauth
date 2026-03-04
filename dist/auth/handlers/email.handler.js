import { PassauthExceptionContext } from "../exceptions/auth.exceptions.js";
import { PassauthEmailFailedToSendEmailException, PassauthInvalidConfirmEmailTokenException, } from "../exceptions/email.exceptions.js";
import { DEFAULT_CONFIRMATION_LINK_EXPIRATION_MS, DEFAULT_RESET_PASSWORD_LINK_EXPIRATION_MS, } from "../constants/email.constants.js";
import { hash, generateToken } from "../utils/auth.utils.js";
import { TemplateTypes } from "../email.enum.js";
export class EmailHandler {
    constructor(options, config) {
        this.options = options;
        this.config = config;
        this.resetPasswordTokens = new Map();
        this.confirmEmailTokens = new Map();
        this.confirmationLinkExpiration = DEFAULT_CONFIRMATION_LINK_EXPIRATION_MS;
        this.resetPasswordLinkExpiration = DEFAULT_RESET_PASSWORD_LINK_EXPIRATION_MS;
        this.saltingRounds = config.saltingRounds;
        const confirmationExpiration = options.emailConfig?.[TemplateTypes.CONFIRM_EMAIL]?.linkExpirationMs;
        if (confirmationExpiration) {
            this.confirmationLinkExpiration = confirmationExpiration;
        }
        const resetPasswordExpiration = options.emailConfig?.[TemplateTypes.RESET_PASSWORD]?.linkExpirationMs;
        if (resetPasswordExpiration) {
            this.resetPasswordLinkExpiration = resetPasswordExpiration;
        }
    }
    async confirmResetPassword(email, token, password) {
        try {
            const isValid = this.verifyToken(email, token, TemplateTypes.RESET_PASSWORD);
            if (isValid) {
                this.resetPasswordTokens.delete(email);
                await this.options.repo.resetPassword(email, await hash(password, this.saltingRounds));
                return { success: true };
            }
            return { success: false };
        }
        catch (error) {
            return { success: false, error };
        }
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
        const now = Date.now();
        if (now > record.exp) {
            this.resetPasswordTokens.delete(email);
            return false;
        }
        return true;
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
        catch (_error) {
            throw new PassauthEmailFailedToSendEmailException(PassauthExceptionContext.EMAIL_CONFIRMATION, email);
        }
    }
    async confirmEmail(email, token) {
        const isValid = this.verifyToken(email, token, TemplateTypes.CONFIRM_EMAIL);
        if (!isValid) {
            throw new PassauthInvalidConfirmEmailTokenException(email);
        }
        this.confirmEmailTokens.delete(email);
        await this.options.repo.confirmEmail(email);
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
            return { success: false, error };
        }
    }
    generateResetPasswordToken(email) {
        const token = generateToken();
        const exp = Date.now() + this.resetPasswordLinkExpiration;
        this.resetPasswordTokens.set(email, { token, exp });
        return token;
    }
    getResetPasswordTemplate(args) {
        const DEFAULT_TEXT = `Reset your password for email ${args.email} by clicking on the following link: ${args.link}`;
        const DEFAULT_HTML = `<p>Reset your password for email ${args.email} by clicking on the following link: <a href="${args.link}">Reset password</a></p>`;
        const customTemplates = this.options.templates?.[TemplateTypes.RESET_PASSWORD]?.(args);
        return {
            text: customTemplates?.text || DEFAULT_TEXT,
            html: customTemplates?.html || DEFAULT_HTML,
        };
    }
    getConfirmEmailTemplate(args) {
        const DEFAULT_TEXT = `Confirm your email ${args.email} by clicking on the following link: ${args.link}`;
        const DEFAULT_HTML = `<p>Confirm your email ${args.email} by clicking on the following link: <a href="${args.link}">Confirm email</a></p>`;
        const customTemplates = this.options.templates?.[TemplateTypes.CONFIRM_EMAIL]?.(args);
        return {
            text: customTemplates?.text || DEFAULT_TEXT,
            html: customTemplates?.html || DEFAULT_HTML,
        };
    }
    getEmailParams(emailArgs, templateType) {
        const overrideParams = this.options.emailConfig?.[templateType]?.email;
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
}
//# sourceMappingURL=email.handler.js.map