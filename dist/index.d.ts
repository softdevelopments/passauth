import type { PassauthConfiguration, PassauthHandler, PassauthHandlerInt, User } from "./auth/auth.types.js";
import { ComposeAug, PluginSpec } from "./plugin/plugin.types.js";
export * from "./auth/index.js";
export * from "./plugin/index.js";
export declare const Passauth: <U extends User, P extends readonly PluginSpec<PassauthHandlerInt<U>, any>[]>(options: PassauthConfiguration<U, P>) => {
    handler: Omit<ComposeAug<PassauthHandler<U>, P>, "_aux">;
    plugins: Record<string, any>;
};
