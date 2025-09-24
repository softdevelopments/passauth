/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuthHandler } from "./auth/auth.handler.js";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions.js";
export * from "./auth/index.js";
export * from "./plugin/index.js";
export const Passauth = (options) => {
    if (!options.secretKey) {
        throw new PassauthMissingConfigurationException("secretKey");
    }
    if (!options.repo) {
        throw new PassauthMissingConfigurationException("repo");
    }
    const handler = new AuthHandler(options, options.repo);
    const plugins = {};
    options.plugins?.forEach((pl) => {
        plugins[pl.name] = { handler: {} };
        pl.handlerInit({
            passauthHandler: handler,
            plugins,
        });
    });
    return { handler: handler, plugins };
};
//# sourceMappingURL=index.js.map