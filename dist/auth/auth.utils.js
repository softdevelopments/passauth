import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { PassauthInvalidAccessTokenException } from "./auth.exceptions";
export const hash = async (password, saltingRounds) => {
    const salt = await bcrypt.genSalt(saltingRounds);
    const hashed = await bcrypt.hash(password, salt);
    return hashed;
};
export const compareHash = async (value, hash) => {
    const isValid = await bcrypt.compare(value, hash);
    return isValid;
};
export const generateAccessToken = ({ userId, secretKey, expiresIn, }) => {
    return jwt.sign({ sub: userId, jti: crypto.randomBytes(16).toString("hex") }, secretKey, {
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
    catch (error) {
        throw new PassauthInvalidAccessTokenException();
    }
};
export const decodeAccessToken = (token) => {
    return jwt.decode(token);
};
//# sourceMappingURL=auth.utils.js.map