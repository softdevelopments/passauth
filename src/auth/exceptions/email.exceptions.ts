import { PassauthException, PassauthExceptionContext } from "./auth.exceptions";

export class PassauthEmailPluginMissingConfigurationException extends PassauthException {
  constructor(key: string) {
    super(
      PassauthExceptionContext.CONFIG,
      "MissingConfiguration",
      `${key} option is required`,
    );
  }
}

export class PassauthEmailNotVerifiedException extends PassauthException {
  constructor(email: string) {
    super(
      PassauthExceptionContext.LOGIN,
      "EmailNotVerified",
      `Email not verified: ${email}`,
    );
  }
}

export class PassauthEmailFailedToSendEmailException extends PassauthException {
  constructor(context: PassauthExceptionContext, email: string) {
    super(context, "FailedToSendEmail", `Failed to send email: ${email}`);
  }
}

export class PassauthInvalidConfirmEmailTokenException extends PassauthException {
  constructor(email: string) {
    super(
      PassauthExceptionContext.EMAIL_CONFIRMATION,
      "InvalidEmailConfimationToken",
      `Failed to confirm email: ${email}`,
    );
  }
}
