import { PassauthPasswordLoginBlockedException } from "../exceptions/password.exceptions";
import type {
  LoginAttemptState,
  NormalizedPasswordPolicy,
  PasswordPolicyConfig,
  PasswordPolicyContext,
  PasswordPolicyContextOperation,
  PasswordLoginAttemptStore,
  PasswordPolicyOptions,
  PasswordValidationResult,
} from "../interfaces/password.types";
import {
  assertPasswordPolicy,
  normalizePasswordPolicy,
  validatePasswordPolicy,
} from "../utils/password-policy.utils";

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export class PasswordPolicyHandler<
  P extends Record<string, unknown> = Record<string, never>,
> {
  private readonly isEnabled: boolean;
  private readonly fallbackPolicy: NormalizedPasswordPolicy;
  private readonly memoryLoginAttemptStore = new Map<string, number>();
  private readonly loginAttemptStore: PasswordLoginAttemptStore<P>;
  private readonly options: PasswordPolicyOptions<P> | undefined;

  constructor(options?: PasswordPolicyConfig<P>) {
    const optionBag =
      options && typeof options === "object" ? options : undefined;

    this.options = optionBag;
    this.isEnabled = options !== undefined;
    this.fallbackPolicy = normalizePasswordPolicy(options ?? true);
    this.loginAttemptStore = optionBag?.loginAttemptStore ?? {
      get: async (email: string, context) =>
        this.memoryLoginAttemptStore.get(this.buildLoginAttemptStoreKey(email, context)) ??
        0,
      set: async (email: string, attempts: number, context) => {
        this.memoryLoginAttemptStore.set(
          this.buildLoginAttemptStoreKey(email, context),
          attempts,
        );
      },
      delete: async (email: string, context) => {
        this.memoryLoginAttemptStore.delete(
          this.buildLoginAttemptStoreKey(email, context),
        );
      },
    };
  }

  isConfigured() {
    return this.isEnabled;
  }

  resolvePolicy(context?: PasswordPolicyContext<P>) {
    return this.getPolicy(context);
  }

  validatePassword(
    password: string,
    context?: PasswordPolicyContext<P>,
  ): PasswordValidationResult {
    return validatePasswordPolicy(password, this.getPolicy(context));
  }

  assertPassword(password: string, context?: PasswordPolicyContext<P>) {
    assertPasswordPolicy(password, this.getPolicy(context));
  }

  async getLoginAttemptState(
    email: string,
    context?: PasswordPolicyContext<P>,
  ): Promise<LoginAttemptState> {
    const resolvedContext = this.resolveContext("getLoginAttemptState", {
      ...context,
      email,
    });
    const policy = this.getPolicy(resolvedContext, resolvedContext.operation);
    const normalizedEmail = normalizeEmail(email);
    const attempts = this.isEnabled
      ? ((await this.loginAttemptStore.get(normalizedEmail, resolvedContext)) ?? 0)
      : 0;
    const maxLoginAttempts = this.isEnabled ? policy.maxLoginAttempts : undefined;
    const isBlocked =
      maxLoginAttempts !== undefined && attempts >= maxLoginAttempts;
    const remainingAttempts =
      maxLoginAttempts === undefined
        ? undefined
        : Math.max(maxLoginAttempts - attempts, 0);

    return {
      email: normalizedEmail,
      scopeKey: resolvedContext.scopeKey,
      attempts,
      remainingAttempts,
      isBlocked,
      maxLoginAttempts,
    };
  }

  async ensureLoginAllowed(
    email: string,
    context?: PasswordPolicyContext<P>,
  ) {
    const state = await this.getLoginAttemptState(email, context);

    if (state.isBlocked && state.maxLoginAttempts !== undefined) {
      throw new PassauthPasswordLoginBlockedException(
        state.email,
        state.maxLoginAttempts,
      );
    }

    return state;
  }

  async registerFailedLogin(
    email: string,
    context?: PasswordPolicyContext<P>,
  ) {
    const resolvedContext = this.resolveContext("login", {
      ...context,
      email,
    });
    const policy = this.getPolicy(resolvedContext, resolvedContext.operation);

    if (!this.isEnabled || policy.maxLoginAttempts === undefined) {
      return {
        email: normalizeEmail(email),
        attempts: 0,
        maxLoginAttempts: undefined,
      };
    }

    const normalizedEmail = normalizeEmail(email);
    const attempts =
      ((await this.loginAttemptStore.get(normalizedEmail, resolvedContext)) ?? 0) + 1;

    await this.loginAttemptStore.set(normalizedEmail, attempts, resolvedContext);

    return {
      email: normalizedEmail,
      attempts,
      maxLoginAttempts: policy.maxLoginAttempts,
    };
  }

  async resetLoginAttempts(
    email: string,
    context?: PasswordPolicyContext<P>,
  ) {
    if (!this.isEnabled) {
      return;
    }

    const resolvedContext = this.resolveContext("resetLoginAttempts", {
      ...context,
      email,
    });

    await this.loginAttemptStore.delete(normalizeEmail(email), resolvedContext);
  }

  private getPolicy(
    context?: PasswordPolicyContext<P>,
    operation: PasswordPolicyContextOperation = "manual",
  ) {
    const resolvedContext = this.resolveContext(operation, context);

    return normalizePasswordPolicy(
      this.options?.resolvePolicy?.(resolvedContext) ?? this.fallbackPolicy,
    );
  }

  private resolveContext(
    operation: PasswordPolicyContextOperation,
    context?: PasswordPolicyContext<P>,
  ) {
    const baseContext = context ?? {};
    const scopeKey =
      baseContext.scopeKey ??
      this.options?.resolveLoginAttemptScope?.({
        ...baseContext,
        operation,
      }) ??
      baseContext.emailParams?.key;

    return {
      ...baseContext,
      operation,
      scopeKey,
    } as const;
  }

  private buildLoginAttemptStoreKey(
    email: string,
    context?: PasswordPolicyContext<P>,
  ) {
    const scopeKey = context?.scopeKey;

    return scopeKey === undefined
      ? normalizeEmail(email)
      : `${normalizeEmail(email)}::${String(scopeKey)}`;
  }
}
