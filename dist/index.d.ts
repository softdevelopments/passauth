import { AuthHandler } from "./auth/auth.handler.js";
import type { PassauthConfiguration, User } from "./auth/auth.types.js";
export * from './auth/index.js';
export * from './plugin/index.js';
export declare const Passauth: <T extends User>(options: PassauthConfiguration<T>) => {
    handler: AuthHandler<T>;
    plugins: import("./index.js").Plugins;
};
