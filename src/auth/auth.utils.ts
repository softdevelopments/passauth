import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

import type { ID } from "./auth.types";
import { InvalidAccessTokenException } from "./auth.exceptions";

export const hash = async (password: string, saltingRounds: number) => {
  const salt = await bcrypt.genSalt(saltingRounds);

  return bcrypt.hash(password, salt);
};

export const generateAccessToken = ({
  userId,
  secretKey,
  expiresIn,
}: {
  userId: ID;
  secretKey: string;
  expiresIn: number;
}) => {
  return jwt.sign(
    { sub: userId, jti: crypto.randomBytes(16).toString("hex") },
    secretKey,
    {
      expiresIn,
    }
  );
};

export const generateRefreshToken = ({ expiresIn }: { expiresIn: number }) => {
  return {
    token: crypto.randomBytes(16).toString("hex"),
    exp: Date.now() + expiresIn,
  };
};

export const verifyAccessToken = (token: string, secretKey: string) => {
  try {
    const decoded = jwt.verify(token, secretKey) as jwt.JwtPayload;

    return decoded;
  } catch (error) {
    throw new InvalidAccessTokenException();
  }
};

export const decodeAccessToken = (token: string) => {
  return jwt.decode(token) as jwt.JwtPayload & { sub: ID };
};
