import jwt from "jsonwebtoken";
import type { ID } from "./auth.types.js";
export declare const hash: (password: string, saltingRounds: number) => Promise<string>;
export declare const compareHash: (value: string, hash: string) => Promise<boolean>;
export declare const generateAccessToken: ({ userId, secretKey, expiresIn, }: {
    userId: ID;
    secretKey: string;
    expiresIn: number;
}) => string;
export declare const generateRefreshToken: ({ expiresIn }: {
    expiresIn: number;
}) => {
    token: string;
    exp: number;
};
export declare const verifyAccessToken: (token: string, secretKey: string) => jwt.JwtPayload;
export declare const decodeAccessToken: (token: string) => jwt.JwtPayload & {
    sub: ID;
};
