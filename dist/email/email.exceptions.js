export class PassauthEmailPluginException extends Error {
    constructor(context, name, message) {
        super(`Passauth email plugin exception: ${message}`);
        this.context = context;
        this.name = name;
        this.origin = "passauth-email-plugin";
    }
}
export class PassauthEmailPluginMissingConfigurationException extends PassauthEmailPluginException {
    constructor(key) {
        super("config", "MissingConfiguration", `${key} option is required`);
    }
}
//# sourceMappingURL=email.exceptions.js.map