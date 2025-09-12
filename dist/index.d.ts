import { AuthHandler } from "./auth/auth.handler";
import type { PassauthConfiguration, User } from "./auth/auth.types";
export * from './auth';
export * from './plugin';
export declare const Passauth: <T extends User>(options: PassauthConfiguration<T>) => {
    handler: AuthHandler<T>;
    plugins: import("./plugin").Plugins;
};
