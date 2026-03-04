/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuthHandler } from "./auth/handlers/auth.handler.js";
import { PassauthMissingConfigurationException } from "./auth/exceptions/auth.exceptions.js";
import { PassauthEmailMissingConfigurationException } from "./auth/exceptions/index.js";
export * from "./auth/index.js";
export * from "./plugin/index.js";
const validateEmailOptions = (options) => {
    if (!options.senderName) {
        throw new PassauthEmailMissingConfigurationException("senderName");
    }
    if (!options.senderEmail) {
        throw new PassauthEmailMissingConfigurationException("senderEmail");
    }
    if (!options.client) {
        throw new PassauthEmailMissingConfigurationException("client");
    }
    if (!options.services) {
        throw new PassauthEmailMissingConfigurationException("services");
    }
    if (!options.repo) {
        throw new PassauthEmailMissingConfigurationException("repo");
    }
};
export const Passauth = (options) => {
    if (!options.secretKey) {
        throw new PassauthMissingConfigurationException("secretKey");
    }
    if (!options.repo) {
        throw new PassauthMissingConfigurationException("repo");
    }
    if (options.email) {
        validateEmailOptions(options.email);
    }
    const sharedComponents = {
        passauthHandler: new AuthHandler(options, options.repo),
        passauthOptions: options,
        plugins: {},
    };
    options.plugins?.forEach((pl) => {
        sharedComponents.plugins[pl.name] = { handler: {} };
        pl.handlerInit(sharedComponents);
    });
    return {
        handler: sharedComponents.passauthHandler,
        plugins: sharedComponents.plugins,
    };
};
//# sourceMappingURL=index.js.map