import type { PassauthHandler, User } from "../auth/auth.types.js";
export type Plugins = Record<string, any>;
export type SharedComponents<U extends User> = {
    passauthHandler: PassauthHandler<U>;
    plugins: Plugins;
};
export type PluginSpec<H, A> = {
    name: string;
    handlerInit: (components: {
        passauthHandler: H;
        plugins: Plugins;
    }) => void;
    __types?: (h: H) => H & A;
};
type ApplyAug<H, P> = P extends {
    __types?: (h: infer HH) => infer R;
} ? HH extends H ? R : H : H;
export type ComposeAug<H, L extends readonly unknown[]> = L extends readonly [
    infer Head,
    ...infer Tail
] ? ComposeAug<ApplyAug<H, Head>, Tail> : H;
export {};
