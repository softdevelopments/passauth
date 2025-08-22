import bcrypt from "bcrypt";
import { EmailSenderRequiredException, InvalidCredentialsException, InvalidRefreshTokenException, InvalidUserException, PassauthEmailAlreadyTakenException, } from "./auth.exceptions";
import { DEFAULT_JWT_EXPIRATION_MS, DEFAULT_REFRESH_EXPIRATION_TOKEN_MS, DEFAULT_SALTING_ROUNDS, } from "./auth.constants";
import { decodeAccessToken, verifyAccessToken, generateAccessToken, generateRefreshToken, hash, } from "./auth.utils";
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
            await this.emailSender?.sendConfirmPasswordEmail(createdUser.email);
        }
        return createdUser;
    }
    async login(params) {
        const user = await this.repo.getUser(params.email);
        if (!user) {
            throw new InvalidUserException(params.email);
        }
        const isValidPassword = await this.comparePasswords(params.password, user.password);
        if (!isValidPassword) {
            throw new InvalidCredentialsException();
        }
        const tokens = this.generateTokens(user.id);
        console.log(".....................", this.refreshTokensLocalChaching);
        return tokens;
    }
    verifyAccessToken(accessToken) {
        const decodedToken = verifyAccessToken(accessToken, this.config.SECRET_KEY);
        if (!decodedToken) {
            throw new InvalidCredentialsException();
        }
        return decodedToken;
    }
    async validateRefreshToken(userId, refreshToken) {
        const cachedToken = this.refreshTokensLocalChaching[userId];
        if (!cachedToken || !cachedToken.token) {
            throw new InvalidRefreshTokenException();
        }
        const hashedToken = await this.hashRefreshToken(refreshToken, userId);
        const isValid = hashedToken === cachedToken.token;
        if (!isValid) {
            throw new InvalidRefreshTokenException();
        }
        const now = Date.now();
        if (now >= cachedToken.exp) {
            throw new InvalidRefreshTokenException();
        }
    }
    async refreshToken(accessToken, refreshToken) {
        const { sub } = decodeAccessToken(accessToken);
        await this.validateRefreshToken(sub, refreshToken);
        const tokens = this.generateTokens(sub);
        return tokens;
    }
    revokeRefreshToken(userId) {
        delete this.refreshTokensLocalChaching[userId];
    }
    async saveRefreshToken(userId, refreshToken, exp) {
        this.refreshTokensLocalChaching[userId] = {
            token: await this.hashRefreshToken(refreshToken, userId),
            exp,
        };
    }
    hashRefreshToken(token, userId) {
        return hash(`${userId}${token}`, 2);
    }
    async resetPassword(email) {
        if (!this.emailSender) {
            throw new EmailSenderRequiredException();
        }
        const success = await this.emailSender.sendResetPasswordEmail(email);
    }
    generateTokens(userId) {
        const accessToken = generateAccessToken({
            userId,
            secretKey: this.config.SECRET_KEY,
            expiresIn: this.config.ACCESS_TOKEN_EXPIRATION_MS,
        });
        const { token: refreshToken, exp } = generateRefreshToken({
            expiresIn: this.config.REFRESH_TOKEN_EXPIRATION_MS,
        });
        this.saveRefreshToken(userId, refreshToken, exp);
        return { accessToken, refreshToken };
    }
    async comparePasswords(password, hash) {
        const isValid = await bcrypt.compare(password, hash);
        return isValid;
    }
}
//# sourceMappingURL=auth.handler.js.map