import { JwtPayload } from "jsonwebtoken";
import type { ID } from "./auth.types.js";
export type AuthJwtPayload<Data> = JwtPayload & {
    sub: ID;
    data: Data | undefined;
};
export declare const hash: (password: string, saltingRounds: number) => Promise<string>;
export declare const compareHash: (value: string, hash: string) => Promise<boolean>;
export declare const generateAccessToken: <D>({ userId, secretKey, expiresIn, data, }: {
    userId: ID;
    secretKey: string;
    expiresIn: number;
    data?: D;
}) => string;
export declare const generateRefreshToken: ({ expiresIn }: {
    expiresIn: number;
}) => {
    token: string;
    exp: number;
};
export declare const verifyAccessToken: <D>(token: string, secretKey: string) => AuthJwtPayload<D>;
export declare const decodeAccessToken: <D>(token: string) => AuthJwtPayload<D>;
