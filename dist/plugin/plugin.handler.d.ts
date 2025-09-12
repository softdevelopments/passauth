import type { AuthHandler } from "../auth/auth.handler.js";
import type { User } from "../auth/auth.types.js";
import type { PluginInit, Plugins } from "./plugin.types.js";
export declare const pluginInit: <U extends User>(plugins: Array<ReturnType<PluginInit<U, any>>>, passauthHandler: AuthHandler<U>) => Plugins;
