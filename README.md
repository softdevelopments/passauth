# passauth

`passauth` is a lightweight TypeScript authentication library for Node.js.
It provides a ready-to-use auth handler with:

- User registration with hashed passwords (`bcrypt`)
- Login with JWT access token + refresh token flow
- Refresh token rotation and revocation
- Optional email confirmation and password reset flows
- Optional built-in password policy validation and login attempt blocking
- Plugin support to extend or override handler behavior with type safety

## Installation

```bash
npm install passauth
```

## Subpath imports

The package exports subpaths, so importing utils using `passauth/auth/utils` is supported:

```ts
import {
  hash,
  compareHash,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  decodeAccessToken,
  generateToken,
  validatePasswordPolicy,
  normalizePasswordPolicy,
  assertPasswordPolicy,
  type AuthJwtPayload,
} from "passauth/auth/utils";
```

### Utils API (`passauth/auth/utils`)

#### `hash(password, saltingRounds)`
Creates a bcrypt hash from a plain password.

- **Parameters**
  - `password` (**required**) — `string`  
    Plain password to hash.
  - `saltingRounds` (**required**) — `number`  
    Number of salt rounds used by bcrypt.
- **Returns**
  - `Promise<string>` — generated password hash.

#### `compareHash(value, hash)`
Compares a plain value against a bcrypt hash.

- **Parameters**
  - `value` (**required**) — `string`  
    Plain text value (typically a password).
  - `hash` (**required**) — `string`  
    Previously generated bcrypt hash.
- **Returns**
  - `Promise<boolean>` — `true` when value matches the hash, otherwise `false`.

#### `generateAccessToken({ userId, secretKey, expiresIn, data? })`
Generates a signed JWT access token.

- **Parameters**
  - `userId` (**required**) — `ID`  
    User identifier used as JWT `sub` claim.
  - `secretKey` (**required**) — `string`  
    Secret used to sign the token.
  - `expiresIn` (**required**) — `number`  
    Token expiration value passed to JWT signing.
  - `data` (**optional**) — `D`  
    Additional custom payload attached to token `data` field.
- **Returns**
  - `string` — signed JWT token.

#### `generateRefreshToken({ expiresIn })`
Generates a refresh token payload.

- **Parameters**
  - `expiresIn` (**required**) — `number`  
    Expiration interval in milliseconds.
- **Returns**
  - `{ token: string; exp: number }` — random token and absolute expiration timestamp (`Date.now() + expiresIn`).

#### `verifyAccessToken(token, secretKey)`
Verifies and decodes a JWT access token.

- **Parameters**
  - `token` (**required**) — `string`  
    JWT access token.
  - `secretKey` (**required**) — `string`  
    Secret used to validate token signature.
- **Returns**
  - `AuthJwtPayload<D>` — decoded JWT payload.
- **Throws**
  - `PassauthInvalidAccessTokenException` when token is invalid or expired.

#### `decodeAccessToken(token)`
Decodes a JWT access token **without signature validation**.

- **Parameters**
  - `token` (**required**) — `string`  
    JWT access token.
- **Returns**
  - `AuthJwtPayload<D>` — decoded payload.

#### `generateToken()`
Generates a random hexadecimal token.

- **Parameters**
  - None.
- **Returns**
  - `string` — random 32-char hex token.

#### `AuthJwtPayload<Data>`
Type helper that describes access token payload returned by decode/verify helpers.

- **Shape**
  - Extends `JwtPayload`
  - `sub: ID`
  - `data: Data | undefined`

## Requirements

- Node.js runtime
- A user repository implementation (database adapter)
- A `secretKey` for JWT signing

## Quick start

```ts
import { Passauth, type AuthRepo, type User } from "passauth";

type AppUser = User & {
  name: string;
};

const users = new Map<string, AppUser>();

const repo: AuthRepo<AppUser> = {
  async getUser(params) {
    if (params.email) {
      return users.get(params.email) ?? null;
    }

    if (params.id) {
      return [...users.values()].find((u) => u.id === params.id) ?? null;
    }

    return null;
  },

  async createUser(params) {
    const user: AppUser = {
      id: Date.now(),
      email: params.email,
      password: params.password,
      isBlocked: false,
      emailVerified: false,
      name: "New User",
    };

    users.set(user.email, user);
    return user;
  },
};

const passauth = Passauth<AppUser>({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
});

// Register
const user = await passauth.handler.register({
  email: "john@example.com",
  password: "StrongPassword123",
});

// Login
const { accessToken, refreshToken } = await passauth.handler.login({
  email: user.email,
  password: "StrongPassword123",
});

// Verify access token
const payload = passauth.handler.verifyAccessToken(accessToken);

// Refresh token pair
const newTokens = await passauth.handler.refreshToken(accessToken, refreshToken);

// Revoke refresh token
await passauth.handler.revokeRefreshToken(user.id);
```

## Password policy

Password protection is now available directly in `passauth`. The feature is opt-in:

If you only want the built-in defaults, enable it with `true`:

```ts
import { Passauth } from "passauth";

const passauth = Passauth({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
  passwordPolicy: true,
});
```

Default rules used by `passwordPolicy: true`:

- `minLength: 6`
- `maxLength: 12`
- `minLowercase: 1`
- `minUppercase: 1`
- `minNumbers: 1`
- `minSpecial: 1`
- `maxLoginAttempts: 3`
- `forbidWhitespace: true`
- `allowedSpecialCharacters: undefined`
- `specialCharacterPattern: /[^A-Za-z0-9\\s]/`

For custom rules or advanced behavior, pass an object:

```ts
import { Passauth, type User } from "passauth";

type AppUser = User & {
  name: string;
};

const passauth = Passauth<AppUser>({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
  passwordPolicy: {
    rules: {
      minLength: 12,
      maxLength: 64,
      minUppercase: 1,
      minLowercase: 1,
      minNumbers: 1,
      minSpecial: 1,
      maxLoginAttempts: 5,
      forbidWhitespace: true,
    },
  },
});

await passauth.handler.register({
  email: "john@example.com",
  password: "StrongPass1!",
  name: "John",
});

const state = await passauth.handler.getLoginAttemptState("john@example.com");
```

When enabled, `passauth` validates passwords during `register(...)` and
`confirmResetPassword(...)`, blocks repeated failed logins, and exposes:
`validatePassword(...)`, `assertPasswordPolicy(...)`, `getPasswordPolicy(...)`,
`getLoginAttemptState(...)`, and `resetLoginAttempts(...)`.

### Password policy configuration reference

#### Practical type

The source code uses generics and helper types internally, but for day-to-day usage you can think of `passwordPolicy` like this:

```ts
type PasswordPolicyRules = {
  minLength?: number;
  maxLength?: number;
  minLowercase?: number;
  minUppercase?: number;
  minNumbers?: number;
  minSpecial?: number;
  maxLoginAttempts?: number;
  forbidWhitespace?: boolean;
  allowedSpecialCharacters?: string | string[];
  specialCharacterPattern?: RegExp;
};

type PasswordPolicyContext = {
  operation:
    | "manual"
    | "register"
    | "login"
    | "confirmResetPassword"
    | "getLoginAttemptState"
    | "resetLoginAttempts";
  email?: string;
  password?: string;
  params?: Record<string, unknown>;
  emailParams?: {
    key?: string;
    linkParams?: Record<string, unknown>;
  };
  scopeKey?: string | number;
};

type PasswordPolicyConfig =
  | true
  | {
      rules?: PasswordPolicyRules;
      resolvePolicy?: (
        context: PasswordPolicyContext,
      ) =>
        | {
            rules: PasswordPolicyRules;
          }
        | undefined;
      resolveLoginAttemptScope?: (
        context: PasswordPolicyContext,
      ) => string | number | undefined;
      loginAttemptStore?: {
        get(
          email: string,
          context?: PasswordPolicyContext,
        ): Promise<number | null | undefined>;
        set(
          email: string,
          attempts: number,
          context?: PasswordPolicyContext,
        ): Promise<void>;
        delete(
          email: string,
          context?: PasswordPolicyContext,
        ): Promise<void>;
      };
    };
```

- `true` enables the built-in default rules exactly as listed above.
- An object enables custom behavior. Use it when you need custom rules, tenant-specific rules, scoped failed-login counters, or an external store.
- `{}` is not valid. If you only want defaults, use `true`.
- At least one of these fields should be present in the object: `rules`, `resolvePolicy`, `resolveLoginAttemptScope`, or `loginAttemptStore`.
- In the real TypeScript types, `params` is inferred from your custom register/login params. It is shown here as `Record<string, unknown>` only to keep the documentation readable.

#### `rules`

```ts
type PasswordPolicyRules = {
  minLength?: number;
  maxLength?: number;
  minLowercase?: number;
  minUppercase?: number;
  minNumbers?: number;
  minSpecial?: number;
  maxLoginAttempts?: number;
  forbidWhitespace?: boolean;
  allowedSpecialCharacters?: string | string[];
  specialCharacterPattern?: RegExp;
};
```

- `minLength?: number`
  Minimum password length. Checked during `register(...)`, `confirmResetPassword(...)`, `validatePassword(...)`, and `assertPasswordPolicy(...)`. Default: `6`.
- `maxLength?: number`
  Maximum password length. Default: `12`. Runtime also accepts `Number.POSITIVE_INFINITY` if you do not want an upper limit.
- `minLowercase?: number`
  Minimum number of lowercase letters required. Default: `1`.
- `minUppercase?: number`
  Minimum number of uppercase letters required. Default: `1`.
- `minNumbers?: number`
  Minimum number of numeric characters required. Default: `1`.
- `minSpecial?: number`
  Minimum number of special characters required. What counts as a special character depends on `allowedSpecialCharacters` or, if that is not set, `specialCharacterPattern`. Default: `1`.
- `maxLoginAttempts?: number`
  Maximum number of failed login attempts allowed before `login(...)` starts throwing `PassauthPasswordLoginBlockedException`. Successful login resets the counter, and you can also clear it manually with `resetLoginAttempts(...)`. Default: `3`.
- `forbidWhitespace?: boolean`
  When `true`, passwords containing spaces, tabs, or other whitespace characters are rejected. Default: `true`.
- `allowedSpecialCharacters?: string | string[]`
  Optional allow-list for special characters. When provided, only the listed characters count as valid special characters, and other special characters are rejected. Each entry must be a single non-alphanumeric, non-whitespace character. Example: `"!@#"` or `["!", "@", "#"]`. Default: `undefined`.
- `specialCharacterPattern?: RegExp`
  Regular expression used to detect special characters when `allowedSpecialCharacters` is not provided. Default: `/[^A-Za-z0-9\s]/`.

All numeric rule fields must be non-negative integers. `maxLoginAttempts` must be greater than `0`.

#### Callback context

```ts
type PasswordPolicyContext = {
  operation:
    | "manual"
    | "register"
    | "login"
    | "confirmResetPassword"
    | "getLoginAttemptState"
    | "resetLoginAttempts";
  email?: string;
  password?: string;
  params?: Record<string, unknown>;
  emailParams?: {
    key?: string;
    linkParams?: Record<string, unknown>;
  };
  scopeKey?: string | number;
};
```

- `operation`
  Tells you which flow is currently running. This is the main switch used inside `resolvePolicy` and `resolveLoginAttemptScope`.
- `email`
  The email involved in the current operation, when available.
- `password`
  The password being validated, when available.
- `params`
  Extra params passed to `register(...)` or `login(...)`. This is usually where tenant, organization, provider, or workspace identifiers live.
- `emailParams`
  Email-related params used in password reset flows.
- `scopeKey`
  The resolved login-attempt scope. You can pass it directly when calling handler methods, or let `resolveLoginAttemptScope` compute it for you.

#### Callback fields

```ts
resolvePolicy?: (
  context: PasswordPolicyContext,
) =>
  | {
      rules: PasswordPolicyRules;
    }
  | undefined;

resolveLoginAttemptScope?: (
  context: PasswordPolicyContext,
) => string | number | undefined;

loginAttemptStore?: {
  get(
    email: string,
    context?: PasswordPolicyContext,
  ): Promise<number | null | undefined>;
  set(
    email: string,
    attempts: number,
    context?: PasswordPolicyContext,
  ): Promise<void>;
  delete(
    email: string,
    context?: PasswordPolicyContext,
  ): Promise<void>;
};
```

- `resolvePolicy(context)`
  Return a different rules object for a specific context. In practice, most applications return `{ rules: ... }` for special cases and `undefined` for everything else.
- `resolveLoginAttemptScope(context)`
  Return a scope key such as `tenantId`, `provider`, or `workspaceId` so the same email can have separate failed-login counters in different scopes.
- `loginAttemptStore.get(email, context)`
  Reads the current failed-attempt counter for the normalized email and resolved scope.
- `loginAttemptStore.set(email, attempts, context)`
  Persists the new failed-attempt counter after an invalid login.
- `loginAttemptStore.delete(email, context)`
  Clears the stored counter after a successful login or an explicit `resetLoginAttempts(...)`.

#### Advanced example

```ts
import { Passauth, type User } from "passauth";

type AuthParams = {
  tenantId: string;
};

const passauth = Passauth<User, AuthParams>({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
  passwordPolicy: {
    rules: {
      minLength: 10,
      maxLength: 64,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSpecial: 1,
      maxLoginAttempts: 5,
      forbidWhitespace: true,
    },
    resolvePolicy: ({ operation, params }) => {
      if (operation === "register" && params?.tenantId === "enterprise") {
        return {
          rules: {
            minLength: 14,
            maxLength: 64,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSpecial: 1,
            maxLoginAttempts: 3,
            forbidWhitespace: true,
          },
        };
      }

      return undefined;
    },
    resolveLoginAttemptScope: ({ params }) => params?.tenantId,
    loginAttemptStore: {
      async get(email, context) {
        const raw = await redis.get(
          `login-attempts:${context?.scopeKey ?? "global"}:${email}`,
        );

        return raw === null ? 0 : Number(raw);
      },
      async set(email, attempts, context) {
        await redis.set(
          `login-attempts:${context?.scopeKey ?? "global"}:${email}`,
          attempts,
        );
      },
      async delete(email, context) {
        await redis.del(`login-attempts:${context?.scopeKey ?? "global"}:${email}`);
      },
    },
  },
});
```

## API overview

`Passauth(config)` returns:

```ts
{
  handler: PassauthHandler,
  plugins: Record<string, { handler: unknown }>
}
```

### Passauth initialization API (`Passauth(config)`)

```ts
const passauth = Passauth({
  secretKey: "your-secret",
  repo,
  saltingRounds: 10,
  accessTokenExpirationMs: 15 * 60 * 1000,
  refreshTokenExpirationMs: 7 * 24 * 60 * 60 * 1000,
  email,
  passwordPolicy,
  plugins,
});
```

Simplified config shape:

```ts
type PassauthConfig = {
  secretKey: string;
  repo: AuthRepo;
  saltingRounds?: number;
  accessTokenExpirationMs?: number;
  refreshTokenExpirationMs?: number;
  email?: EmailHandlerOptions;
  passwordPolicy?: PasswordPolicyConfig;
  plugins?: unknown[];
};
```

Simplified return value:

```ts
type PassauthInstance = {
  handler: PassauthHandler;
  plugins: Record<string, { handler: unknown }>;
};
```

- You normally do not need to write generic types manually. TypeScript usually infers them from your `repo`, your extra params, and your plugins.
- `handler` is the main auth API you use in the app.
- `plugins` is an object keyed by plugin name, with each plugin exposing its own `handler`.

#### Configuration fields (detailed)

- `secretKey` (**required**) — `string`  
  Secret used to sign and validate JWT access tokens.

- `repo` (**required**) — `AuthRepo`  
  Your persistence adapter used by auth operations (lookup user, create user, optional token cache).

- `saltingRounds` (**optional**) — `number` (default: `10`)  
  Salt rounds used for password hashing.

- `accessTokenExpirationMs` (**optional**) — `number` (default: `15 * 60 * 1000`)  
  Access token expiration time in milliseconds.

- `refreshTokenExpirationMs` (**optional**) — `number` (default: `7 * 24 * 60 * 60 * 1000`)  
  Refresh token expiration time in milliseconds.

- `email` (**optional**) — `EmailHandlerOptions`  
  Enables email confirmation and reset-password flows when provided.

- `passwordPolicy` (**optional**) — `PasswordPolicyConfig`  
  Enables built-in password validation and failed-login tracking. When set to `true`, passauth uses the default rule set; `{}` is not a valid shortcut.

- `plugins` (**optional**) — `array`  
  List of plugins that can override/extend the handler API.

#### Return value of `Passauth(config)`

- `handler` — main auth API object (`PassauthHandler` plus any plugin augmentations).
- `plugins` — plugin namespace object keyed by plugin `name`.

### Repository contract (`AuthRepo`)

You must implement:

- `getUser(param: Partial<User>): Promise<User | null>`
- `createUser<P>(params: RegisterParams<P>): Promise<User>`
  - `RegisterParams<P>` always includes `email` and `password`, and can include extra fields.

Optional methods for persistent refresh token cache (recommended in production):

- `getCachedToken(userId)`
- `saveCachedToken(userId, token, expiresInMs)`
- `deleteCachedToken(userId)`

If cache methods are not provided, passauth keeps refresh tokens in memory.

### Main handler methods

Below is a detailed reference of the methods exposed by `passauth.handler`.

#### `register(params)`
Creates a new user with a hashed password.

- **Arguments**
  - `params` (**required**) — `RegisterParams`
    - `email` (**required**) — `string`
    - `password` (**required**) — `string`
    - Additional fields are supported (`register<T>(params: RegisterParams<T>)`) and forwarded to your `repo.createUser`.
- **Returns**
  - `Promise<U>` — the created user entity returned by your repository.

#### `login(params, jwtUserFields?)`
Authenticates a user and returns access/refresh tokens.

- **Arguments**
  - `params` (**required**) — `LoginParams`
    - `email` (**required**) — `string`
    - `password` (**required**) — `string`
    - Additional fields are supported (`login<T>(params: LoginParams<T>, ...)`) and forwarded to your `repo.getUser`.
  - `jwtUserFields` (**optional**) — `Array<keyof U>`
    - If provided, only these user fields are injected into token payload `data`.
- **Returns**
  - `Promise<{ accessToken: string; refreshToken: string }>`

#### `verifyAccessToken(accessToken)`
Validates and decodes an access token.

- **Arguments**
  - `accessToken` (**required**) — `string`
- **Returns**
  - `AuthJwtPayload<D>` — decoded payload with token claims (and optional `data`).

#### `refreshToken(accessToken, refreshToken)`
Issues a new access/refresh token pair using a valid refresh token.

- **Arguments**
  - `accessToken` (**required**) — `string`
  - `refreshToken` (**required**) — `string`
- **Returns**
  - `Promise<{ accessToken: string; refreshToken: string }>`

#### `revokeRefreshToken(userId)`
Revokes the currently cached refresh token for a user.

- **Arguments**
  - `userId` (**required**) — `ID` (`string | number`)
- **Returns**
  - `Promise<void>`

#### `generateTokens(userId, data?)`
Generates a new token pair and stores a hashed refresh token.

- **Arguments**
  - `userId` (**required**) — `ID` (`string | number`)
  - `data` (**optional**) — generic payload `D` to embed in access token.
- **Returns**
  - `Promise<{ accessToken: string; refreshToken: string }>`

#### `sendResetPasswordEmail(email, emailParams?)`
Creates and sends a password reset email (when email module is configured).

- **Arguments**
  - `email` (**required**) — `string`
  - `emailParams` (**optional**) — `{ key?: string; linkParams?: Record<string, unknown> }`
    `key` scopes the cached token for this email. `linkParams` adds extra params to the reset link.
- **Returns**
  - `Promise<{ success: boolean; error?: unknown }>`

#### `confirmResetPassword(email, token, password, emailParams?)`
Validates a reset token and updates the user password.

- **Arguments**
  - `email` (**required**) — `string`
  - `token` (**required**) — `string`
  - `password` (**required**) — `string` (new plain password, hashed internally)
  - `emailParams` (**optional**) — `{ key?: string; linkParams?: Record<string, unknown> }`
    `key` must match the one used when the reset token was generated. `linkParams` are forwarded to `email.repo.resetPassword(...)`.
- **Returns**
  - `Promise<{ success: boolean; error?: unknown }>`

#### `sendConfirmPasswordEmail(email, emailParams?)`
Creates and sends an email confirmation message.

- **Arguments**
  - `email` (**required**) — `string`
  - `emailParams` (**optional**) — `{ key?: string; linkParams?: Record<string, unknown> }`
    `key` scopes the cached token for this email. `linkParams` adds extra params to the confirmation link.
- **Returns**
  - `Promise<{ success: boolean; error?: unknown }>`

#### `confirmEmail(email, token, emailParams?)`
Validates the email confirmation token and marks email as confirmed via your email repo.

- **Arguments**
  - `email` (**required**) — `string`
  - `token` (**required**) — `string`
  - `emailParams` (**optional**) — `{ key?: string; linkParams?: Record<string, unknown> }`
    `key` must match the one used when the confirmation token was generated. `linkParams` are forwarded to `email.repo.confirmEmail(...)`.
- **Returns**
  - `Promise<void>`

## Optional email flows

To enable confirmation and reset-password flows, provide an `email` config.

Tokens for confirmation and reset are stored by `email`, and inside each email by `emailParams.key`. Generating a new token with the same `email + key` invalidates the previous token for security reasons. Generating tokens with different keys keeps them isolated. If `key` is not provided, the library uses the email itself as the key.

### `EmailHandlerOptions` API (detailed)

```ts
type EmailHandlerOptions = {
  senderName: string;
  senderEmail: string;
  client: EmailClient;
  emailConfig?: {
    [TemplateTypes.CONFIRM_EMAIL]?: {
      email?: Omit<Partial<SendEmailArgs>, "text" | "html" | "to">;
      linkExpirationMs?: number;
    };
    [TemplateTypes.RESET_PASSWORD]?: {
      email?: Omit<Partial<SendEmailArgs>, "text" | "html" | "to">;
      linkExpirationMs?: number;
    };
  };
  templates?: {
    [TemplateTypes.CONFIRM_EMAIL]?: (params: { email: string; link: string }) => {
      text: string;
      html: string;
    };
    [TemplateTypes.RESET_PASSWORD]?: (params: { email: string; link: string }) => {
      text: string;
      html: string;
    };
  };
  services: {
    createResetPasswordLink(
      email: string,
      token: string,
      linkParams?: Record<string, unknown>
    ): Promise<string>;
    createConfirmEmailLink(
      email: string,
      token: string,
      linkParams?: Record<string, unknown>
    ): Promise<string>;
  };
  repo: {
    confirmEmail(email: string, emailParams?: ConfirmEmailParams): Promise<boolean>;
    resetPassword(
      email: string,
      password: string,
      emailParams?: ResetPasswordEmailParams
    ): Promise<boolean>;
  };
};
```

#### Email fields (required vs optional)

- `senderName` (**required**) — `string`  
  Default sender display name.

- `senderEmail` (**required**) — `string`  
  Default sender email address (`from`).

- `client` (**required**) — `EmailClient`  
  Delivery adapter with `send(emailData: SendEmailArgs): Promise<void>`.

- `services` (**required**) — object with async link builders:
  - `createResetPasswordLink(email, token, linkParams?): Promise<string>`
  - `createConfirmEmailLink(email, token, linkParams?): Promise<string>`

- `repo` (**required**) — object with async persistence actions:
  - `confirmEmail(email, emailParams?): Promise<boolean>`
  - `resetPassword(email, password, emailParams?): Promise<boolean>`

- `emailConfig` (**optional**) — per-template overrides:
  - `linkExpirationMs?: number` to customize token/link validity
  - `email?: { senderName?: string; from?: string; subject?: string }` to override metadata

- `templates` (**optional**) — custom template functions per email type.
  - Input: `{ email: string; link: string }`
  - Output: `{ text: string; html: string }`

Example configuration:

```ts
import { Passauth, TemplateTypes, type EmailHandlerOptions } from "passauth";

const emailOptions: EmailHandlerOptions = {
  senderName: "Acme Auth",
  senderEmail: "no-reply@acme.com",
  client: {
    async send(emailData) {
      // Integrate with your provider (SES, Resend, SendGrid, etc.)
      console.log("Sending email", emailData);
    },
  },
  services: {
    async createResetPasswordLink(email, token, linkParams) {
      const query = new URLSearchParams({
        email,
        token,
        ...Object.fromEntries(
          Object.entries(linkParams ?? {}).map(([key, value]) => [
            key,
            String(value),
          ]),
        ),
      });

      return `https://app.acme.com/reset-password?${query.toString()}`;
    },
    async createConfirmEmailLink(email, token, linkParams) {
      const query = new URLSearchParams({
        email,
        token,
        ...Object.fromEntries(
          Object.entries(linkParams ?? {}).map(([key, value]) => [
            key,
            String(value),
          ]),
        ),
      });

      return `https://app.acme.com/confirm-email?${query.toString()}`;
    },
  },
  repo: {
    async confirmEmail(email, emailParams) {
      // Mark user as emailVerified=true in your DB
      // emailParams?.linkParams can be used for redirect/tracking context
      return true;
    },
    async resetPassword(email, hashedPassword, emailParams) {
      // Save the hashed password in your DB
      // emailParams?.linkParams can be used for redirect/tracking context
      return true;
    },
  },
  emailConfig: {
    [TemplateTypes.CONFIRM_EMAIL]: {
      linkExpirationMs: 1000 * 60 * 60 * 24,
      email: {
        subject: "Please confirm your email",
      },
    },
  },
};
```

Usage with additional reset-link params:

```ts
await passauth.handler.sendResetPasswordEmail("user@acme.com", {
  key: "tenant-a",
  linkParams: {
    key: "tenant-a",
    redirectTo: "/settings/security",
    source: "password-reset",
  },
});
```

`key` scopes the cached token. Reissuing a reset for the same `email + key` invalidates the previous token. `linkParams` are passed into `createResetPasswordLink(...)`, so you can append redirect or tracking query params to the emailed URL.

When the user comes back from that link, you can pass the same params into `confirmResetPassword(...)`:

```ts
await passauth.handler.confirmResetPassword(
  "user@acme.com",
  tokenFromUrl,
  "new-password",
  {
    key: "tenant-a",
    linkParams: {
      key: "tenant-a",
      redirectTo: "/settings/security",
      source: "password-reset",
    },
  },
);
```

Those params are forwarded to `email.repo.resetPassword(...)`, which lets your application finalize the reset with the same contextual data used to build the link.

Usage with additional confirmation-link params:

```ts
await passauth.handler.sendConfirmPasswordEmail("user@acme.com", {
  key: "tenant-a",
  linkParams: {
    key: "tenant-a",
    redirectTo: "/settings/security",
    source: "billing-upgrade",
  },
});
```

`key` scopes the cached token. Reissuing a confirmation for the same `email + key` invalidates the previous token. `linkParams` are passed into `createConfirmEmailLink(...)`, so you can append redirect or tracking query params to the emailed URL.

When the user comes back from that link, you can pass the same params into `confirmEmail(...)`:

```ts
await passauth.handler.confirmEmail("user@acme.com", tokenFromUrl, {
  key: "tenant-a",
  linkParams: {
    key: "tenant-a",
    redirectTo: "/settings/security",
    source: "billing-upgrade",
  },
});
```

Those params are forwarded to `email.repo.confirmEmail(...)`, which lets your application finalize the confirmation with the same contextual data used to build the link.

## Plugins

passauth supports plugins that can override or extend `handler` methods.
A plugin is an object with:

- `name`
- `handlerInit({ passauthHandler, passauthOptions, plugins })`
- optional `__types` helper for TypeScript augmentation

Minimal example:

```ts
import { Passauth, type PluginSpec, type User, type PassauthHandlerInt } from "passauth";

type HelloAPI = {
  hello(): string;
};

const helloPlugin = (): PluginSpec<User, PassauthHandlerInt<User>, HelloAPI> => ({
  name: "hello",
  handlerInit: ({ passauthHandler }) => {
    (passauthHandler as PassauthHandlerInt<User> & HelloAPI).hello = () => "hello";
  },
  __types: () => undefined as unknown as HelloAPI,
});

const passauth = Passauth({
  secretKey: "secret",
  repo,
  plugins: [helloPlugin()] as const,
});

console.log(passauth.handler.hello());
```

## Error handling

All library errors extend `PassauthException` and include:

- `origin: "passauth"`
- `context: string`
- `name: string`
- `message: string`
- `log: string`

### Available `PassauthExceptions`

#### Base

- `PassauthException`
  - Base class for all errors in the library.

#### Configuration errors

- `PassauthMissingConfigurationException`
  - Thrown when required top-level config is missing (for example: `secretKey`, `repo`).

- `PassauthEmailMissingConfigurationException`
  - Thrown when required email config fields are missing (for example: `senderName`, `senderEmail`, `client`, `services`, `repo`).

#### Registration/Login errors

- `PassauthEmailAlreadyTakenException`
  - Thrown on `register` when a user with the same email already exists.

- `PassauthInvalidUserException`
  - Thrown on `login` when user is not found.

- `PassauthBlockedUserException`
  - Thrown on `login` when user is blocked (`isBlocked = true`).

- `PassauthInvalidCredentialsException`
  - Thrown on `login` when password does not match.

- `PassauthEmailNotVerifiedException`
  - Thrown on `login` when email features are enabled and `emailVerified` is false.

#### Token errors

- `PassauthInvalidAccessTokenException`
  - Thrown when access token verification fails (invalid/expired token).

- `PassauthInvalidRefreshTokenException`
  - Thrown when refresh token is invalid, expired, missing, or revoked.

#### Email flow errors

- `PassauthEmailFailedToSendEmailException`
  - Thrown when email send operation fails (confirmation or registration confirmation flow).

- `PassauthInvalidConfirmEmailTokenException`
  - Thrown when email confirmation token is invalid or expired.

### Error context values

`context` is one of `PassauthExceptionContext` values:

- `config`
- `register`
- `login`
- `email confirmation`

Handle these exceptions in your service/controller layer and map them to your HTTP or RPC error format.

## License

ISC
