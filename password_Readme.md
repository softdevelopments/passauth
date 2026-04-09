# @passauth/safe-password-plugin

Password policy plugin for `passauth`.

It validates passwords during `register` and `confirmResetPassword`, and it can
also block login attempts after a configurable number of failures. Failed login
attempts can be stored in memory or in an external cache/database service.
The plugin can also consume the same contextual params that `passauth` forwards
internally, which makes it compatible with custom auth flows such as
multi-tenant setups.

## Installation

```bash
npm install @passauth/safe-password-plugin passauth
```

## Usage

```ts
import { Passauth } from "passauth";
import { SafePasswordPlugin } from "@passauth/safe-password-plugin";

const passauth = Passauth({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
  plugins: [
    SafePasswordPlugin({
      rules: {
        minLength: 12,
        maxLength: 64,
        minUppercase: 1,
        minLowercase: 1,
        minNumbers: 1,
        minSpecial: 1,
        maxLoginAttempts: 5,
        forbidWhitespace: true,
        allowedSpecialCharacters: "!@#$%",
      },
      loginAttemptStore: {
        async get(email) {
          return redis.get(`login-attempts:${email}`).then((value) =>
            value ? Number(value) : 0,
          );
        },
        async set(email, attempts) {
          await redis.set(`login-attempts:${email}`, String(attempts));
        },
        async delete(email) {
          await redis.del(`login-attempts:${email}`);
        },
      },
    }),
  ] as const,
});

await passauth.handler.register({
  email: "john@example.com",
  password: "StrongPassword1!",
});
```

### Multi-tenant usage

`passauth` forwards extra params from `register(...)` and `login(...)` to your
repository, and forwards `emailParams.key/linkParams` through the reset flow.
The plugin can consume that same context to resolve password policy and scope
login attempts.

```ts
import { Passauth, type User } from "passauth";
import { SafePasswordPlugin } from "@passauth/safe-password-plugin";

type TenantParams = {
  tenantId: string;
};

const passauth = Passauth({
  secretKey: process.env.JWT_SECRET ?? "dev-secret",
  repo,
  plugins: [
    SafePasswordPlugin<User, TenantParams>({
      rules: {
        minLength: 8,
        minUppercase: 1,
        minLowercase: 1,
        minNumbers: 1,
        minSpecial: 1,
        maxLoginAttempts: 5,
      },
      resolvePolicy: ({ params }) =>
        params?.tenantId === "enterprise"
          ? {
              rules: {
                minLength: 14,
                minUppercase: 1,
                minLowercase: 1,
                minNumbers: 1,
                minSpecial: 1,
                maxLoginAttempts: 3,
              },
            }
          : undefined,
      resolveLoginAttemptScope: ({ params, emailParams }) =>
        params?.tenantId ?? emailParams?.key,
      loginAttemptStore: {
        async get(email, context) {
          const scope = context?.scopeKey ?? "default";

          return redis.get(`login-attempts:${scope}:${email}`).then((value) =>
            value ? Number(value) : 0,
          );
        },
        async set(email, attempts, context) {
          const scope = context?.scopeKey ?? "default";

          await redis.set(`login-attempts:${scope}:${email}`, String(attempts));
        },
        async delete(email, context) {
          const scope = context?.scopeKey ?? "default";

          await redis.del(`login-attempts:${scope}:${email}`);
        },
      },
    }),
  ] as const,
});

await passauth.handler.register({
  email: "john@acme.com",
  password: "StrongPassword1!",
  tenantId: "enterprise",
});

await passauth.handler.login({
  email: "john@acme.com",
  password: "StrongPassword1!",
  tenantId: "enterprise",
});
```

## API

### `SafePasswordPlugin(options)`

Creates a typed Passauth plugin.

```ts
function SafePasswordPlugin<
  U extends User,
  P extends Record<string, unknown> = Record<string, never>,
>(
  options: SafePasswordPolicyOptions<P>,
): PluginSpec<U, PassauthHandlerInt<U>, SafePasswordPluginAPI<P>>;
```

### `SafePasswordPolicyOptions`

```ts
type SafePasswordContext<P = Record<string, never>> = Readonly<{
  operation?:
    | "manual"
    | "register"
    | "login"
    | "confirmResetPassword"
    | "getLoginAttemptState"
    | "resetLoginAttempts";
  email?: string;
  password?: string;
  params?: P;
  emailParams?: ResetPasswordEmailParams;
  scopeKey?: string | number;
}>;

type SafePasswordPolicyOptions<P = Record<string, never>> = {
  rules?: SafePasswordRules;
  resolvePolicy?: (
    context: SafePasswordContext<P> & {
      operation: NonNullable<SafePasswordContext["operation"]>;
    },
  ) => SafePasswordPolicyOptions<P> | NormalizedSafePasswordPolicy | undefined;
  resolveLoginAttemptScope?: (
    context: SafePasswordContext<P> & {
      operation: NonNullable<SafePasswordContext["operation"]>;
    },
  ) => string | number | undefined;
  loginAttemptStore?: SafePasswordLoginAttemptStore<P>;
};

type SafePasswordRules = {
  minLength?: number;
  maxLength?: number;
  minLowercase?: number;
  minUppercase?: number;
  minNumbers?: number;
  minSpecial?: number;
  maxLoginAttempts?: number;
  forbidWhitespace?: boolean;
  allowedSpecialCharacters?: string | readonly string[];
  specialCharacterPattern?: RegExp;
};

type SafePasswordLoginAttemptStore<P = Record<string, never>> = {
  get(
    email: string,
    context?: SafePasswordContext<P>,
  ): Promise<number | null | undefined>;
  set(
    email: string,
    attempts: number,
    context?: SafePasswordContext<P>,
  ): Promise<void>;
  delete(email: string, context?: SafePasswordContext<P>): Promise<void>;
};
```

Notes:

- If `rules` is omitted, the plugin uses the default rule set.
- `resolvePolicy` can override the password policy using the same contextual
  params that `passauth` forwards internally.
- `resolveLoginAttemptScope` can isolate login attempts per tenant/provider/etc.
  when your auth flow depends on extra params.
- If `allowedSpecialCharacters` is provided, only those special characters are accepted.
- If `maxLoginAttempts` is provided, login is blocked for the email after the configured number of failed attempts.
- If `loginAttemptStore` is not provided, failed login attempts are stored in memory.
- If `loginAttemptStore` is provided, the plugin uses that service to read,
  persist, and clear failed login attempts, and forwards the resolved context.
- By default, the in-memory store keys attempts by normalized email; use
  `resolveLoginAttemptScope` when you need multi-tenant isolation.
- `specialCharacterPattern` is used only when `allowedSpecialCharacters` is not provided.

Default rule values:

- `minLength: 6`
- `maxLength: 12`
- `minLowercase: 1`
- `minUppercase: 1`
- `minNumbers: 1`
- `minSpecial: 1`
- `maxLoginAttempts: 3`
- `forbidWhitespace: true`

### Utility helpers

```ts
function validatePasswordPolicy(
  password: string,
  options: SafePasswordPolicyOptions | NormalizedSafePasswordPolicy,
): PasswordValidationResult;

function assertPasswordPolicy(
  password: string,
  options: SafePasswordPolicyOptions | NormalizedSafePasswordPolicy,
): void;

function normalizeSafePasswordPolicy(
  options: SafePasswordPolicyOptions | NormalizedSafePasswordPolicy,
): NormalizedSafePasswordPolicy;
```

`assertPasswordPolicy(...)` throws `PassauthPasswordPolicyException` when validation fails.

## Handler Methods Added By The Plugin

The plugin augments `passauth.handler` with the following methods.

### `validatePassword(password, context?)`

```ts
validatePassword(
  password: string,
  context?: SafePasswordContext<P>,
): PasswordValidationResult;
```

Parameters:

- `password: string`
- `context?: SafePasswordContext<P>`

Returns:

```ts
type PasswordValidationResult = Readonly<{
  success: boolean;
  policy: NormalizedSafePasswordPolicy;
  metrics: PasswordMetrics;
  violations: PasswordPolicyViolation[];
}>;
```

Related nested types:

```ts
type PasswordMetrics = Readonly<{
  length: number;
  lowercase: number;
  uppercase: number;
  numbers: number;
  special: number;
  disallowedSpecial: number;
  whitespace: number;
}>;

type PasswordPolicyViolation = Readonly<{
  code:
    | "MIN_LENGTH"
    | "MAX_LENGTH"
    | "MIN_LOWERCASE"
    | "MIN_UPPERCASE"
    | "MIN_NUMBERS"
    | "MIN_SPECIAL"
    | "DISALLOWED_SPECIAL"
    | "WHITESPACE_NOT_ALLOWED";
  message: string;
  expected: number | boolean;
  actual: number;
}>;
```

### `assertPasswordPolicy(password, context?)`

```ts
assertPasswordPolicy(password: string, context?: SafePasswordContext<P>): void;
```

Parameters:

- `password: string`
- `context?: SafePasswordContext<P>`

Returns:

- `void`

Throws:

- `PassauthPasswordPolicyException` when the password does not satisfy the configured policy

### `getPasswordPolicy(context?)`

```ts
getPasswordPolicy(context?: SafePasswordContext<P>): NormalizedSafePasswordPolicy;
```

Parameters:

- `context?: SafePasswordContext<P>`

Returns:

```ts
type NormalizedSafePasswordPolicy = Readonly<{
  minLength: number;
  maxLength: number;
  minLowercase: number;
  minUppercase: number;
  minNumbers: number;
  minSpecial: number;
  maxLoginAttempts: number | undefined;
  forbidWhitespace: boolean;
  allowedSpecialCharacters: readonly string[] | undefined;
  specialCharacterPattern: RegExp;
}>;
```

### `getLoginAttemptState(email, context?)`

```ts
getLoginAttemptState(
  email: string,
  context?: SafePasswordContext<P>,
): Promise<LoginAttemptState>;
```

Parameters:

- `email: string`
- `context?: SafePasswordContext<P>`

Returns:

```ts
type LoginAttemptState = Readonly<{
  email: string;
  scopeKey: string | number | undefined;
  attempts: number;
  remainingAttempts: number | undefined;
  isBlocked: boolean;
  maxLoginAttempts: number | undefined;
}>;
```

### `resetLoginAttempts(email, context?)`

```ts
resetLoginAttempts(
  email: string,
  context?: SafePasswordContext<P>,
): Promise<void>;
```

Parameters:

- `email: string`
- `context?: SafePasswordContext<P>`

Returns:

- `Promise<void>`

## Exceptions

- `PassauthPasswordPolicyException`
- `PassauthPasswordPolicyConfigurationException`
- `PassauthPasswordLoginBlockedException`
