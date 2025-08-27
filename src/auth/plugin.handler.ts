import type { UserEmailSenderPlugin } from "../email/email.types";
import type { AuthHandler } from "./auth.handler";
import type { User } from "./auth.types";
import type { PluginInit, Plugins } from "./plugin.types";

export const pluginInit = <U extends User>(
  plugins: Array<ReturnType<PluginInit<U, any>>>,
  passauthHandler: AuthHandler<U>
) => {
  const pluginsCollection = plugins.reduce((acc, plugin) => {
    acc[plugin.name] = {
      handler: plugin.handlerInit({ passauthHandler, plugins: acc }),
    };

    return acc;
  }, {} as Plugins);

  return pluginsCollection;
};
