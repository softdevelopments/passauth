import type { ResetPasswordEmailParams } from "./email.types";

export type PasswordPolicyRules = {
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

export type PasswordPolicyContextOperation =
  | "manual"
  | "register"
  | "login"
  | "confirmResetPassword"
  | "getLoginAttemptState"
  | "resetLoginAttempts";

export type PasswordPolicyContext<
  P extends Record<string, unknown> = Record<string, never>,
> = Readonly<{
  operation?: PasswordPolicyContextOperation;
  email?: string | undefined;
  password?: string | undefined;
  params?: P | undefined;
  emailParams?: ResetPasswordEmailParams | undefined;
  scopeKey?: string | number | undefined;
}>;

export type PasswordPolicyResolver<
  P extends Record<string, unknown> = Record<string, never>,
> = (
  context: Readonly<
    PasswordPolicyContext<P> & {
      operation: PasswordPolicyContextOperation;
    }
  >,
) => PasswordPolicyOptions<P> | NormalizedPasswordPolicy | undefined;

export type PasswordLoginAttemptScopeResolver<
  P extends Record<string, unknown> = Record<string, never>,
> = (
  context: Readonly<
    PasswordPolicyContext<P> & {
      operation: PasswordPolicyContextOperation;
    }
  >,
) => string | number | undefined;

export type PasswordLoginAttemptStore<
  P extends Record<string, unknown> = Record<string, never>,
> = {
  get(
    email: string,
    context?: Readonly<
      PasswordPolicyContext<P> & {
        operation: PasswordPolicyContextOperation;
      }
    >,
  ): Promise<number | null | undefined>;
  set(
    email: string,
    attempts: number,
    context?: Readonly<
      PasswordPolicyContext<P> & {
        operation: PasswordPolicyContextOperation;
      }
    >,
  ): Promise<void>;
  delete(
    email: string,
    context?: Readonly<
      PasswordPolicyContext<P> & {
        operation: PasswordPolicyContextOperation;
      }
    >,
  ): Promise<void>;
};

export type PasswordPolicyOptions<
  P extends Record<string, unknown> = Record<string, never>,
> = {
  rules?: PasswordPolicyRules;
  resolvePolicy?: PasswordPolicyResolver<P>;
  resolveLoginAttemptScope?: PasswordLoginAttemptScopeResolver<P>;
  loginAttemptStore?: PasswordLoginAttemptStore<P>;
};

export type NormalizedPasswordPolicy = Readonly<{
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

export type PasswordMetrics = Readonly<{
  length: number;
  lowercase: number;
  uppercase: number;
  numbers: number;
  special: number;
  disallowedSpecial: number;
  whitespace: number;
}>;

export type PasswordPolicyViolationCode =
  | "MIN_LENGTH"
  | "MAX_LENGTH"
  | "MIN_LOWERCASE"
  | "MIN_UPPERCASE"
  | "MIN_NUMBERS"
  | "MIN_SPECIAL"
  | "DISALLOWED_SPECIAL"
  | "WHITESPACE_NOT_ALLOWED";

export type PasswordPolicyViolation = Readonly<{
  code: PasswordPolicyViolationCode;
  message: string;
  expected: number | boolean;
  actual: number;
}>;

export type PasswordValidationResult = Readonly<{
  success: boolean;
  policy: NormalizedPasswordPolicy;
  metrics: PasswordMetrics;
  violations: PasswordPolicyViolation[];
}>;

export type LoginAttemptState = Readonly<{
  email: string;
  scopeKey: string | number | undefined;
  attempts: number;
  remainingAttempts: number | undefined;
  isBlocked: boolean;
  maxLoginAttempts: number | undefined;
}>;
