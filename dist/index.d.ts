import { AuthHandler } from "./auth/auth.handler";
import type { PassauthConfiguration, User } from "./auth/auth.types";
export declare const Passauth: <T extends User>(options: PassauthConfiguration<T>) => {
    handler: AuthHandler<T>;
    plugins: import("./plugin/plugin.types").Plugins;
};
//# sourceMappingURL=index.d.ts.map