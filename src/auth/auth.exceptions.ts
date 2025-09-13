export class PassauthException extends Error {
  public origin = "passauth";

  public message: string;

  constructor(public context: string, public name: string, message: string) {
    super(`Passauth exception: ${message}`);

    this.message = `Passauth exception: ${message}`;
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

export class PassauthInvalidUserException extends PassauthException {
  constructor(email: string) {
    super("login", "InvalidUser", `Invalid email: ${email}`);
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
