/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import type {
  PassauthConfiguration,
  PassauthHandler,
  PassauthHandlerInt,
  User,
} from "./auth/auth.types";
import {
  ComposeAug,
  PluginSpec,
  SharedComponents,
} from "./plugin/plugin.types";

export * from "./auth/index";
export * from "./plugin/index";

export const Passauth = <
  U extends User,
  P extends readonly PluginSpec<U, PassauthHandlerInt<U>, any>[],
>(
  options: PassauthConfiguration<U, P>
) => {
  if (!options.secretKey) {
    throw new PassauthMissingConfigurationException("secretKey");
  }
  if (!options.repo) {
    throw new PassauthMissingConfigurationException("repo");
  }

  const sharedComponents = {
    passauthHandler: new AuthHandler<U>(options, options.repo),
    passauthOptions: options,
    plugins: {} as Record<string, any>,
  } as SharedComponents<U>;

  options.plugins?.forEach((pl) => {
    sharedComponents.plugins[pl.name] = { handler: {} };
    pl.handlerInit(sharedComponents);
  });

  type HandlerWithPlugins = Omit<ComposeAug<PassauthHandler<U>, P>, "_aux">;

  return {
    handler: sharedComponents.passauthHandler as unknown as HandlerWithPlugins,
    plugins: sharedComponents.plugins,
  };
};
