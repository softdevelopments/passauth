/* eslint-disable @typescript-eslint/no-explicit-any */
import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import type {
  PassauthConfiguration,
  PassauthHandler,
  PassauthHandlerInt,
  User,
} from "./auth/auth.types";
import { ComposeAug, PluginSpec } from "./plugin/plugin.types";

export * from "./auth/index";
export * from "./plugin/index";

export const Passauth = <
  U extends User,
  P extends readonly PluginSpec<PassauthHandlerInt<U>, any>[], // base único
>(
  options: PassauthConfiguration<U, P>
) => {
  if (!options.secretKey) {
    throw new PassauthMissingConfigurationException("secretKey");
  }
  if (!options.repo) {
    throw new PassauthMissingConfigurationException("repo");
  }

  const handler = new AuthHandler<U>(options, options.repo);
  const plugins: Record<string, any> = {};

  options.plugins?.forEach((pl) => {
    plugins[pl.name] = { handler: {} };
    pl.handlerInit({
      passauthHandler: handler as unknown as PassauthHandlerInt<U>,
      plugins,
    });
  });

  type HandlerWithPlugins = Omit<ComposeAug<PassauthHandler<U>, P>, "_aux">;

  return { handler: handler as unknown as HandlerWithPlugins, plugins };
};
