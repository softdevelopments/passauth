import { PassauthException, PassauthExceptionContext } from "./auth.exceptions.js";
export declare class PassauthEmailMissingConfigurationException extends PassauthException {
    constructor(key: string);
}
export declare class PassauthEmailNotVerifiedException extends PassauthException {
    constructor(email: string);
}
export declare class PassauthEmailFailedToSendEmailException extends PassauthException {
    constructor(context: PassauthExceptionContext, email: string);
}
export declare class PassauthInvalidConfirmEmailTokenException extends PassauthException {
    constructor(email: string);
}
