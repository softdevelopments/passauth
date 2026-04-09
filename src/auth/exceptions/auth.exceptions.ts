export class PassauthException extends Error {
  public origin = "passauth";
  public log: string;

  constructor(
    public context: string,
    public name: string,
    message: string,
  ) {
    super(message);

    this.log = `Passauth exception: ${message}`;
  }
}

export enum PassauthExceptionContext {
  REGISTER = "register",
  CONFIG = "config",
  LOGIN = "login",
  EMAIL_CONFIRMATION = "email confirmation",
  PASSWORD_POLICY = "password policy",
}

export class PassauthMissingConfigurationException extends PassauthException {
  constructor(key: string) {
    super(
      PassauthExceptionContext.CONFIG,
      "MissingConfiguration",
      `Passauth exception: ${key} option is required`,
    );
  }
}

export class PassauthEmailAlreadyTakenException extends PassauthException {
  constructor() {
    super(PassauthExceptionContext.REGISTER, "EmailAlreadyTaken", "Email already taken");
  }
}

export class PassauthInvalidUserException extends PassauthException {
  constructor(data: string) {
    super(PassauthExceptionContext.LOGIN, "InvalidUser", `Invalid user: ${data}`);
  }
}

export class PassauthBlockedUserException extends PassauthException {
  constructor(email: string) {
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
