export class PassauthException extends Error {
    constructor(context, name, message) {
        super(message);
        this.context = context;
        this.name = name;
        this.origin = "passauth";
        this.log = `Passauth exception: ${message}`;
    }
}
export var PassauthExceptionContext;
(function (PassauthExceptionContext) {
    PassauthExceptionContext["REGISTER"] = "register";
    PassauthExceptionContext["CONFIG"] = "config";
    PassauthExceptionContext["LOGIN"] = "login";
    PassauthExceptionContext["EMAIL_CONFIRMATION"] = "email confirmation";
})(PassauthExceptionContext || (PassauthExceptionContext = {}));
export class PassauthMissingConfigurationException extends PassauthException {
    constructor(key) {
        super(PassauthExceptionContext.CONFIG, "MissingConfiguration", `Passauth exception: ${key} option is required`);
    }
}
export class PassauthEmailAlreadyTakenException extends PassauthException {
    constructor() {
        super(PassauthExceptionContext.REGISTER, "EmailAlreadyTaken", "Email already taken");
    }
}
export class PassauthInvalidUserException extends PassauthException {
    constructor(data) {
        super(PassauthExceptionContext.LOGIN, "InvalidUser", `Invalid user: ${data}`);
    }
}
export class PassauthBlockedUserException extends PassauthException {
    constructor(email) {
        super(PassauthExceptionContext.LOGIN, "BlockedUser", `User is blocked: ${email}`);
    }
}
export class PassauthInvalidCredentialsException extends PassauthException {
    constructor() {
        super(PassauthExceptionContext.LOGIN, "InvalidCredentials", "Invalid email or password");
    }
}
export class PassauthInvalidAccessTokenException extends PassauthException {
    constructor() {
        super(PassauthExceptionContext.LOGIN, "InvalidAccessToken", "Invalid access token");
    }
}
export class PassauthInvalidRefreshTokenException extends PassauthException {
    constructor() {
        super(PassauthExceptionContext.LOGIN, "InvalidRefreshToken", "Invalid refresh token");
    }
}
//# sourceMappingURL=auth.exceptions.js.map