import crypto from "crypto";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { InvalidAccessTokenException } from "./auth.exceptions";
export const hash = async (password, saltingRounds) => {
    const salt = await bcrypt.genSalt(saltingRounds);
    return bcrypt.hash(password, salt);
};
export const generateAccessToken = ({ userId, secretKey, expiresIn, }) => {
    return jwt.sign({ sub: userId, jti: crypto.randomBytes(16).toString("hex") }, secretKey, {
        expiresIn,
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
        throw new InvalidAccessTokenException();
    }
};
export const decodeAccessToken = (token) => {
    return jwt.decode(token);
};
//# sourceMappingURL=auth.utils.js.map