import { PassauthException, PassauthExceptionContext } from "./auth.exceptions.js";
export class PassauthEmailMissingConfigurationException extends PassauthException {
    constructor(key) {
        super(PassauthExceptionContext.CONFIG, "MissingConfiguration", `${key} option is required`);
    }
}
export class PassauthEmailNotVerifiedException extends PassauthException {
    constructor(email) {
        super(PassauthExceptionContext.LOGIN, "EmailNotVerified", `Email not verified: ${email}`);
    }
}
export class PassauthEmailFailedToSendEmailException extends PassauthException {
    constructor(context, email) {
        super(context, "FailedToSendEmail", `Failed to send email: ${email}`);
    }
}
export class PassauthInvalidConfirmEmailTokenException extends PassauthException {
    constructor(email) {
        super(PassauthExceptionContext.EMAIL_CONFIRMATION, "InvalidEmailConfimationToken", `Failed to confirm email: ${email}`);
    }
}
//# sourceMappingURL=email.exceptions.js.map