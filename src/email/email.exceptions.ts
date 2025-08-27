export class PassauthEmailPluginException extends Error {
  public origin = "passauth-email-plugin";

  constructor(public context: string, public name: string, message: string) {
    super(`Passauth email plugin exception: ${message}`);
  }
}

export class PassauthEmailPluginMissingConfigurationException extends PassauthEmailPluginException {
  constructor(key: string) {
    super("config", "MissingConfiguration", `${key} option is required`);
  }
}

export class PassauthEmailNotVerifiedException extends PassauthEmailPluginException {
  constructor(email: string) {
    super("login", "EmailNotVerified", `Email not verified: ${email}`);
  }
}
