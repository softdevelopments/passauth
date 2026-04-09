import { PassauthException, PassauthExceptionContext } from "./auth.exceptions";
import type {
  NormalizedPasswordPolicy,
  PasswordMetrics,
  PasswordPolicyViolation,
} from "../interfaces/password.types";

export class PassauthPasswordPolicyException extends PassauthException {
  readonly violations: PasswordPolicyViolation[];
  readonly metrics: PasswordMetrics;
  readonly policy: NormalizedPasswordPolicy;

  constructor(params: {
    violations: PasswordPolicyViolation[];
    metrics: PasswordMetrics;
    policy: NormalizedPasswordPolicy;
  }) {
    super(
      PassauthExceptionContext.PASSWORD_POLICY,
      "PasswordPolicy",
      params.violations.map((violation) => violation.message).join(" "),
    );

    this.violations = params.violations;
    this.metrics = params.metrics;
    this.policy = params.policy;
  }
}

export class PassauthPasswordLoginBlockedException extends PassauthException {
  readonly email: string;
  readonly maxLoginAttempts: number;

  constructor(email: string, maxLoginAttempts: number) {
    super(
      PassauthExceptionContext.LOGIN,
      "PasswordLoginBlocked",
      `Login blocked for "${email}" after ${maxLoginAttempts} failed attempts.`,
    );

    this.email = email;
    this.maxLoginAttempts = maxLoginAttempts;
  }
}

export class PassauthPasswordPolicyConfigurationException extends PassauthException {
  constructor(message: string) {
    super(
      PassauthExceptionContext.CONFIG,
      "PasswordPolicyConfiguration",
      message,
    );
  }
}
