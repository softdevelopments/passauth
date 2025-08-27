import type { AuthHandler } from "../auth/auth.handler";
import type { User } from "../auth/auth.types";

export type Plugins = {
  [key: string]: {
    handler: any;
  };
};

export type PluginInitParams<T extends { [key: string]: any }> = {
  [K in keyof T]: T[K];
};

export type SharedComponents<U extends User> = {
  passauthHandler: AuthHandler<U>;
  plugins: Plugins;
};

export type PluginInit<U extends User, O extends { [key: string]: any }> = (
  params: PluginInitParams<O>
) => {
  name: string;
  handlerInit: (components: SharedComponents<U>) => any;
};
