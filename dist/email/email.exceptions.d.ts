export declare class PassauthEmailPluginException extends Error {
    context: string;
    name: string;
    origin: string;
    constructor(context: string, name: string, message: string);
}
export declare class PassauthEmailPluginMissingConfigurationException extends PassauthEmailPluginException {
    constructor(key: string);
}
//# sourceMappingURL=email.exceptions.d.ts.map