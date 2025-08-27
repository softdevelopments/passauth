import type { AuthHandler } from "../auth/auth.handler";
import type { User } from "../auth/auth.types";
import type { PluginInit, Plugins } from "./plugin.types";
export declare const pluginInit: <U extends User>(plugins: Array<ReturnType<PluginInit<U, any>>>, passauthHandler: AuthHandler<U>) => Plugins;
//# sourceMappingURL=plugin.handler.d.ts.map