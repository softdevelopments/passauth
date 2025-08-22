export declare class PassauthException extends Error {
    context: string;
    name: string;
    origin: string;
    constructor(context: string, name: string, message: string);
}
export declare class PassauthMissingConfigurationException extends PassauthException {
    constructor(key: string);
}
export declare class PassauthEmailAlreadyTakenException extends PassauthException {
    constructor();
}
export declare class InvalidUserException extends PassauthException {
    constructor(email: string);
}
export declare class InvalidCredentialsException extends PassauthException {
    constructor();
}
export declare class InvalidAccessTokenException extends PassauthException {
    constructor();
}
export declare class InvalidRefreshTokenException extends PassauthException {
    constructor();
}
export declare class EmailSenderRequiredException extends PassauthException {
    constructor();
}
//# sourceMappingURL=auth.exceptions.d.ts.map