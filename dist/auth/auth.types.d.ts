import type { PluginInit } from "../plugin/plugin.types.js";
export type ID = string | number;
export type User = {
    id: ID;
    email: string;
    password: string;
};
export type RegisterParams = {
    email: string;
    password: string;
};
export type LoginParams = {
    email: string;
    password: string;
};
export interface AuthRepo<T extends User> {
    getUser(param: Partial<T>): Promise<T | null>;
    createUser(params: RegisterParams): Promise<T>;
    getCachedToken?: (userId: ID) => Promise<string | undefined | null>;
    saveCachedToken?: (userId: ID, token: string, expiresInMs: number) => Promise<void>;
    deleteCachedToken?: (userId: ID) => Promise<void>;
}
export type HandlerOptions = {
    secretKey: string;
    saltingRounds?: number;
    accessTokenExpirationMs?: number;
    refreshTokenExpirationMs?: number;
};
export type PassauthConfiguration<U extends User> = HandlerOptions & {
    repo: AuthRepo<U>;
    plugins?: Array<ReturnType<PluginInit<U, any>>>;
};
