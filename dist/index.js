import { AuthHandler } from "./auth/auth.handler.js";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions.js";
import { pluginInit } from "./plugin/plugin.handler.js";
export * from './auth/index.js';
export * from './plugin/index.js';
export const Passauth = (options) => {
    if (!options.secretKey) {
        throw new PassauthMissingConfigurationException("secretKey");
    }
    if (!options.repo) {
        throw new PassauthMissingConfigurationException("repo");
    }
    const handler = new AuthHandler(options, options.repo);
    const plugins = pluginInit(options?.plugins || [], handler);
    return { handler, plugins };
};
//# sourceMappingURL=index.js.map