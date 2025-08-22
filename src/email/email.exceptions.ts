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
