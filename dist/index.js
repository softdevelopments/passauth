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
// type PassauthConfiguration = {
//   secretKey: string;
//   saltingRounds?: number;
//   accessTokenExpirationMs?: number;
//   refreshTokenExpirationMs?: number;
//   repo: AuthRepo<User>;
// }
// Passauth({
//   secretKey: 'your-secret-key',
//   saltingRounds: 12,
//   accessTokenExpirationMs: 1000 * 60 * 3, // 3 minutes
//   refreshTokenExpirationMs: 1000 * 60 * 60 * 24, // 24 h
// })
//# sourceMappingURL=index.js.map