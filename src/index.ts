import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import type { PassauthConfiguration, User } from "./auth/auth.types";
import { pluginInit } from "./plugin/plugin.handler";

export * from "./auth/index";
export * from "./plugin/index";

export const Passauth = <T extends User>(options: PassauthConfiguration<T>) => {
  if (!options.secretKey) {
    throw new PassauthMissingConfigurationException("secretKey");
  }

  if (!options.repo) {
    throw new PassauthMissingConfigurationException("repo");
  }

  const handler = new AuthHandler<T>(options, options.repo);

  const plugins = pluginInit(options?.plugins || [], handler);

  return { handler, plugins };
};
