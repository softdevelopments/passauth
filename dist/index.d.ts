import { ComposeAug, PluginSpec } from "./plugin/plugin.types.js";
import type { PassauthConfiguration, PassauthHandler, PassauthHandlerInt, User } from "./auth/interfaces/index.js";
export * from "./auth/index.js";
export * from "./plugin/index.js";
export declare const Passauth: <U extends User, P extends readonly PluginSpec<U, PassauthHandlerInt<U>, any>[]>(options: PassauthConfiguration<U, P>) => {
    handler: Omit<ComposeAug<PassauthHandler<U>, P>, "_aux">;
    plugins: import("./index.js").Plugins;
};
