import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import { pluginInit } from "./plugin/plugin.handler";
export * from './auth/index';
export * from './plugin/index';
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