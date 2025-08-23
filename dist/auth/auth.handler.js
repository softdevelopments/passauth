import bcrypt from "bcrypt";
import { PassauthEmailSenderRequiredException, PassauthInvalidCredentialsException, PassauthInvalidRefreshTokenException, PassauthInvalidUserException, PassauthEmailAlreadyTakenException, PassauthInvalidAccessTokenException, PassauthEmailNotVerifiedException, } from "./auth.exceptions";
import { DEFAULT_JWT_EXPIRATION_MS, DEFAULT_REFRESH_EXPIRATION_TOKEN_MS, DEFAULT_SALTING_ROUNDS, } from "./auth.constants";
import { decodeAccessToken, verifyAccessToken, generateAccessToken, generateRefreshToken, hash, compareHash, } from "./auth.utils";
export class AuthHandler {
    constructor(options, repo, emailSender) {
        this.repo = repo;
        this.emailSender = emailSender;
        this.refreshTokensLocalChaching = {};
        this.config = {
            SALTING_ROUNDS: options.saltingRounds || DEFAULT_SALTING_ROUNDS,
            ACCESS_TOKEN_EXPIRATION_MS: options.accessTokenExpirationMs || DEFAULT_JWT_EXPIRATION_MS,
            REFRESH_TOKEN_EXPIRATION_MS: options.refreshTokenExpirationMs || DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
            REQUIRE_EMAIL_CONFIRMATION: options.requireEmailConfirmation || false,
            SECRET_KEY: options.secretKey,
        };
    }
    async register(params) {
        const existingUser = await this.repo.getUser(params.email);
        if (existingUser) {
            throw new PassauthEmailAlreadyTakenException();
        }
        const createdUser = await this.repo.createUser({
            ...params,
            password: await hash(params.password, this.config.SALTING_ROUNDS),
        });
        if (this.config.REQUIRE_EMAIL_CONFIRMATION) {
            const { success } = await this.emailSender.sendConfirmPasswordEmail(createdUser.email);
            return { user: createdUser, emailSent: success };
        }
        return { user: createdUser, emailSent: false };
    }
    async login(params) {
        const user = await this.repo.getUser(params.email);
        if (!user) {
            throw new PassauthInvalidUserException(params.email);
        }
        if (this.config.REQUIRE_EMAIL_CONFIRMATION && !user.emailVerified) {
            throw new PassauthEmailNotVerifiedException(params.email);
        }
        const isValidPassword = await compareHash(params.password, user.password);
        if (!isValidPassword) {
            throw new PassauthInvalidCredentialsException();
        }
        const tokens = this.generateTokens(user.id);
        return tokens;
    }
    verifyAccessToken(accessToken) {
        const decodedToken = verifyAccessToken(accessToken, this.config.SECRET_KEY);
        if (!decodedToken) {
            throw new PassauthInvalidAccessTokenException();
        }
        return decodedToken;
    }
    async refreshToken(accessToken, refreshToken) {
        const { sub } = decodeAccessToken(accessToken);
        await this.validateRefreshToken(sub, refreshToken);
        const tokens = await this.generateTokens(sub);
        return tokens;
    }
    revokeRefreshToken(userId) {
        delete this.refreshTokensLocalChaching[userId];
    }
    async validateRefreshToken(userId, refreshToken) {
        const cachedToken = this.refreshTokensLocalChaching[userId];
        if (!cachedToken || !cachedToken.token) {
            throw new PassauthInvalidRefreshTokenException();
        }
        const isValid = await this.compareRefeshToken(refreshToken, userId, cachedToken.token);
        if (!isValid) {
            throw new PassauthInvalidRefreshTokenException();
        }
        const now = Date.now();
        if (now >= cachedToken.exp) {
            throw new PassauthInvalidRefreshTokenException();
        }
    }
    async saveRefreshToken(userId, refreshToken, exp) {
        const hashedToken = await this.hashRefreshToken(refreshToken, userId);
        const tokenData = {
            token: hashedToken,
            exp,
        };
        this.refreshTokensLocalChaching[userId] = tokenData;
    }
    async hashRefreshToken(token, userId) {
        const hashed = await hash(`${userId}${token}`, 2);
        return hashed;
    }
    async compareRefeshToken(token, userId, hashedToken) {
        const isValid = await compareHash(`${userId}${token}`, hashedToken);
        return isValid;
    }
    async resetPassword(email) {
        if (!this.emailSender) {
            throw new PassauthEmailSenderRequiredException();
        }
        const success = await this.emailSender.sendResetPasswordEmail(email);
        return success;
    }
    async generateTokens(userId) {
        const accessToken = generateAccessToken({
            userId,
            secretKey: this.config.SECRET_KEY,
            expiresIn: this.config.ACCESS_TOKEN_EXPIRATION_MS,
        });
        const { token: refreshToken, exp } = generateRefreshToken({
            expiresIn: this.config.REFRESH_TOKEN_EXPIRATION_MS,
        });
        await this.saveRefreshToken(userId, refreshToken, exp);
        return { accessToken, refreshToken };
    }
}
//# sourceMappingURL=auth.handler.js.map