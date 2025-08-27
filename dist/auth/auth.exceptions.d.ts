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
export declare class PassauthInvalidUserException extends PassauthException {
    constructor(email: string);
}
export declare class PassauthInvalidCredentialsException extends PassauthException {
    constructor();
}
export declare class PassauthInvalidAccessTokenException extends PassauthException {
    constructor();
}
export declare class PassauthInvalidRefreshTokenException extends PassauthException {
    constructor();
}
//# sourceMappingURL=auth.exceptions.d.ts.map