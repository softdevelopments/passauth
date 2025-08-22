export class PassauthException extends Error {
  public origin = "passauth";

  constructor(public context: string, public name: string, message: string) {
    super(`Passauth exception: ${message}`);
  }
}

export class PassauthMissingConfigurationException extends PassauthException {
  constructor(key: string) {
    super("config", "MissingConfiguration", `${key} option is required`);
  }
}

export class PassauthEmailAlreadyTakenException extends PassauthException {
  constructor() {
    super("register", "EmailAlreadyTaken", "Email already taken");
  }
}

export class InvalidUserException extends PassauthException {
  constructor(email: string) {
    super("login", "InvalidUser", `Invalid email: ${email}`);
  }
}

export class InvalidCredentialsException extends PassauthException {
  constructor() {
    super("login", "InvalidCredentials", "Invalid email or password");
  }
}

export class InvalidAccessTokenException extends PassauthException {
  constructor() {
    super("login", "InvalidAccessToken", "Invalid access token");
  }
}

export class InvalidRefreshTokenException extends PassauthException {
  constructor() {
    super("login", "InvalidRefreshToken", "Invalid refresh token");
  }
}

export class EmailSenderRequiredException extends PassauthException {
  constructor() {
    super(
      "config",
      "EmailSenderPluginRequired",
      "Email sender plugin is required"
    );
  }
}
