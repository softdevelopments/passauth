export class PassauthException extends Error {
    constructor(context, name, message) {
        super(message);
        this.context = context;
        this.name = name;
        this.origin = "passauth";
        this.log = `Passauth exception: ${message}`;
    }
}
export class PassauthMissingConfigurationException extends PassauthException {
    constructor(key) {
        super("config", "MissingConfiguration", `Passauth exception: ${key} option is required`);
    }
}
export class PassauthEmailAlreadyTakenException extends PassauthException {
    constructor() {
        super("register", "EmailAlreadyTaken", "Email already taken");
    }
}
export class PassauthInvalidUserException extends PassauthException {
    constructor(data) {
        super("login", "InvalidUser", `Invalid user: ${data}`);
    }
}
export class PassauthBlockedUserException extends PassauthException {
    constructor(email) {
        super("login", "BlockedUser", `User is blocked: ${email}`);
    }
}
export class PassauthInvalidCredentialsException extends PassauthException {
    constructor() {
        super("login", "InvalidCredentials", "Invalid email or password");
    }
}
export class PassauthInvalidAccessTokenException extends PassauthException {
    constructor() {
        super("login", "InvalidAccessToken", "Invalid access token");
    }
}
export class PassauthInvalidRefreshTokenException extends PassauthException {
    constructor() {
        super("login", "InvalidRefreshToken", "Invalid refresh token");
    }
}
//# sourceMappingURL=auth.exceptions.js.map