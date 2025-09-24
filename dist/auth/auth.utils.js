import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { PassauthInvalidAccessTokenException } from "./auth.exceptions.js";
export const hash = async (password, saltingRounds) => {
    const salt = await bcrypt.genSalt(saltingRounds);
    const hashed = await bcrypt.hash(password, salt);
    return hashed;
};
export const compareHash = async (value, hash) => {
    const isValid = await bcrypt.compare(value, hash);
    return isValid;
};
export const generateAccessToken = ({ userId, secretKey, expiresIn, data, }) => {
    return jwt.sign({ sub: userId, jti: crypto.randomBytes(16).toString("hex"), data }, secretKey, {
        expiresIn: `${expiresIn}`,
    });
};
export const generateRefreshToken = ({ expiresIn }) => {
    return {
        token: crypto.randomBytes(16).toString("hex"),
        exp: Date.now() + expiresIn,
    };
};
export const verifyAccessToken = (token, secretKey) => {
    try {
        const decoded = jwt.verify(token, secretKey);
        return decoded;
    }
    catch (_error) {
        throw new PassauthInvalidAccessTokenException();
    }
};
export const decodeAccessToken = (token) => {
    return jwt.decode(token);
};
//# sourceMappingURL=auth.utils.js.map