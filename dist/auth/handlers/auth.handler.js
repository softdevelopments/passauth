import { PassauthInvalidCredentialsException, PassauthInvalidRefreshTokenException, PassauthInvalidUserException, PassauthEmailAlreadyTakenException, PassauthInvalidAccessTokenException, PassauthBlockedUserException, PassauthExceptionContext, } from "../exceptions/auth.exceptions.js";
import { PassauthEmailFailedToSendEmailException, PassauthEmailNotVerifiedException, } from "../exceptions/email.exceptions.js";
import { DEFAULT_JWT_EXPIRATION_MS, DEFAULT_REFRESH_EXPIRATION_TOKEN_MS, DEFAULT_SALTING_ROUNDS, } from "../constants/auth.constants.js";
import { decodeAccessToken, verifyAccessToken, generateAccessToken, generateRefreshToken, hash, compareHash, } from "../utils/auth.utils.js";
import { EmailHandler } from "./email.handler.js";
export class AuthHandler {
    constructor(options, repo) {
        this.options = options;
        this.repo = repo;
        this.refreshTokensLocalChaching = {};
        this._name = "Passauth";
        this.config = {
            SALTING_ROUNDS: options.saltingRounds || DEFAULT_SALTING_ROUNDS,
            ACCESS_TOKEN_EXPIRATION_MS: options.accessTokenExpirationMs || DEFAULT_JWT_EXPIRATION_MS,
            REFRESH_TOKEN_EXPIRATION_MS: options.refreshTokenExpirationMs || DEFAULT_REFRESH_EXPIRATION_TOKEN_MS,
            SECRET_KEY: options.secretKey,
        };
        this._aux = {
            config: this.config,
            validateRefreshToken: typeof this.validateRefreshToken,
            saveRefreshToken: typeof this.saveRefreshToken,
            hashRefreshToken: typeof this.hashRefreshToken,
            compareRefeshToken: typeof this.compareRefeshToken,
        };
        if (options.email) {
            this.emailHandler = new EmailHandler(options.email, {
                saltingRounds: this.config.SALTING_ROUNDS,
            });
        }
    }
    async register(params) {
        const existingUser = await this.repo.getUser({
            email: params.email,
        });
        if (existingUser) {
            throw new PassauthEmailAlreadyTakenException();
        }
        const createdUser = await this.repo.createUser({
            ...params,
            password: await hash(params.password, this.config.SALTING_ROUNDS),
        });
        if (params.email && this.emailHandler) {
            const { success } = await this.emailHandler.sendConfirmPasswordEmail(createdUser.email);
            if (!success) {
                throw new PassauthEmailFailedToSendEmailException(PassauthExceptionContext.REGISTER, params.email);
            }
        }
        return createdUser;
    }
    async sendResetPasswordEmail(email) {
        if (!this.emailHandler) {
            return { success: false };
        }
        return this.emailHandler.sendResetPasswordEmail(email);
    }
    async sendConfirmPasswordEmail(email) {
        if (!this.emailHandler) {
            return { success: false };
        }
        return this.emailHandler.sendConfirmPasswordEmail(email);
    }
    async confirmEmail(email, token) {
        if (!this.emailHandler) {
            throw new Error("Email handler not configured");
        }
        return this.emailHandler.confirmEmail(email, token);
    }
    async confirmResetPassword(email, token, password) {
        if (!this.emailHandler) {
            return { success: false };
        }
        return this.emailHandler.confirmResetPassword(email, token, password);
    }
    async login(params, jwtUserFields) {
        const user = await this.repo.getUser({ email: params.email });
        if (!user) {
            throw new PassauthInvalidUserException(params.email);
        }
        if (user.isBlocked) {
            throw new PassauthBlockedUserException(params.email);
        }
        if (this.emailHandler && !user.emailVerified) {
            throw new PassauthEmailNotVerifiedException(params.email);
        }
        const isValidPassword = await compareHash(params.password, user.password);
        if (!isValidPassword) {
            throw new PassauthInvalidCredentialsException();
        }
        const jwtData = jwtUserFields
            ? jwtUserFields.reduce((params, userKey) => {
                params[userKey] = user[userKey];
                return params;
            }, {})
            : undefined;
        const tokens = this.generateTokens(user.id, jwtData);
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
        const { sub, data } = decodeAccessToken(accessToken);
        await this.validateRefreshToken(sub, refreshToken);
        const tokens = await this.generateTokens(sub, data);
        return tokens;
    }
    async revokeRefreshToken(userId) {
        if (this.repo.deleteCachedToken) {
            await this.repo.deleteCachedToken(userId);
        }
        else {
            delete this.refreshTokensLocalChaching[userId];
        }
    }
    async generateTokens(userId, data) {
        const accessToken = generateAccessToken({
            userId,
            secretKey: this.config.SECRET_KEY,
            expiresIn: this.config.ACCESS_TOKEN_EXPIRATION_MS,
            data,
        });
        const { token: refreshToken, exp } = generateRefreshToken({
            expiresIn: this.config.REFRESH_TOKEN_EXPIRATION_MS,
        });
        await this.saveRefreshToken(userId, refreshToken, exp);
        return { accessToken, refreshToken };
    }
    async getCachedRefreshToken(userId) {
        if (this.repo.getCachedToken) {
            const cachedToken = await this.repo.getCachedToken(userId);
            return cachedToken;
        }
        const cachedToken = this.refreshTokensLocalChaching[userId];
        const now = Date.now();
        if (!cachedToken) {
            return null;
        }
        if (now >= cachedToken.exp) {
            return null;
        }
        return cachedToken.token;
    }
    async validateRefreshToken(userId, refreshToken) {
        const cachedToken = await this.getCachedRefreshToken(userId);
        if (!cachedToken) {
            throw new PassauthInvalidRefreshTokenException();
        }
        const isValid = await this.compareRefeshToken(refreshToken, userId, cachedToken);
        if (!isValid) {
            throw new PassauthInvalidRefreshTokenException();
        }
    }
    async saveRefreshToken(userId, refreshToken, exp) {
        const hashedToken = await this.hashRefreshToken(refreshToken, userId);
        const tokenData = {
            token: hashedToken,
            exp,
        };
        if (this.repo.saveCachedToken) {
            await this.repo.saveCachedToken(userId, tokenData.token, this.config.REFRESH_TOKEN_EXPIRATION_MS);
        }
        else {
            this.refreshTokensLocalChaching[userId] = tokenData;
        }
    }
    async hashRefreshToken(token, userId) {
        const hashed = await hash(`${userId}${token}`, 2);
        return hashed;
    }
    async compareRefeshToken(token, userId, hashedToken) {
        const isValid = await compareHash(`${userId}${token}`, hashedToken);
        return isValid;
    }
}
//# sourceMappingURL=auth.handler.js.map