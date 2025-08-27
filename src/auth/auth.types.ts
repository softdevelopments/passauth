import type { JwtPayload } from "jsonwebtoken";
import type { PluginInit } from "../plugin/plugin.types";

export type ID = string | number;

export type User = {
  id: ID;
  email: string;
  password: string;
  emailVerified?: boolean;
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
  getUser(email: string): Promise<T | null>;
  createUser(params: RegisterParams): Promise<T>;
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
