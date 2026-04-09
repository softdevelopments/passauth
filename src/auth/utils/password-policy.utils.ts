import {
  PassauthPasswordPolicyConfigurationException,
  PassauthPasswordPolicyException,
} from "../exceptions/password.exceptions";
import type {
  NormalizedPasswordPolicy,
  PasswordMetrics,
  PasswordPolicyConfig,
  PasswordPolicyViolation,
  PasswordPolicyRules,
} from "../interfaces/password.types";

const DEFAULT_SPECIAL_CHARACTER_PATTERN = /[^A-Za-z0-9\s]/;
const DEFAULT_PASSWORD_RULES = {
  minLength: 6,
  maxLength: 12,
  minLowercase: 1,
  minUppercase: 1,
  minNumbers: 1,
  minSpecial: 1,
  maxLoginAttempts: 3,
  forbidWhitespace: true,
} as const;
const INTEGER_FIELDS = [
  "minLength",
  "maxLength",
  "minLowercase",
  "minUppercase",
  "minNumbers",
  "minSpecial",
  "maxLoginAttempts",
] as const;

const cloneRegex = (pattern: RegExp) => new RegExp(pattern.source, pattern.flags);

const isGenericSpecialCharacter = (character: string) =>
  !/[a-z]/.test(character) &&
  !/[A-Z]/.test(character) &&
  !/[0-9]/.test(character) &&
  !/\s/.test(character);

const normalizeAllowedSpecialCharacters = (
  allowedSpecialCharacters?: string | readonly string[],
) => {
  if (allowedSpecialCharacters === undefined) {
    return undefined;
  }

  const entries =
    typeof allowedSpecialCharacters === "string"
      ? [...allowedSpecialCharacters]
      : allowedSpecialCharacters;

  if (!Array.isArray(entries)) {
    throw new PassauthPasswordPolicyConfigurationException(
      '"allowedSpecialCharacters" must be a string or an array of characters.',
    );
  }

  const normalized = [...new Set(entries)];

  normalized.forEach((character) => {
    if (character.length !== 1) {
      throw new PassauthPasswordPolicyConfigurationException(
        '"allowedSpecialCharacters" must contain single characters only.',
      );
    }

    if (!isGenericSpecialCharacter(character)) {
      throw new PassauthPasswordPolicyConfigurationException(
        `"${character}" is not a valid special character.`,
      );
    }
  });

  return normalized;
};

const countMatches = (
  password: string,
  predicate: (character: string) => boolean,
) =>
  [...password].reduce(
    (count, character) => count + Number(predicate(character)),
    0,
  );

const getPasswordMetrics = (
  password: string,
  policy: NormalizedPasswordPolicy,
): PasswordMetrics => ({
  length: password.length,
  lowercase: countMatches(password, (character) => /[a-z]/.test(character)),
  uppercase: countMatches(password, (character) => /[A-Z]/.test(character)),
  numbers: countMatches(password, (character) => /[0-9]/.test(character)),
  special: countMatches(password, (character) => {
    if (policy.allowedSpecialCharacters) {
      return policy.allowedSpecialCharacters.includes(character);
    }

    policy.specialCharacterPattern.lastIndex = 0;

    return policy.specialCharacterPattern.test(character);
  }),
  disallowedSpecial: countMatches(password, (character) => {
    if (!isGenericSpecialCharacter(character)) {
      return false;
    }

    if (!policy.allowedSpecialCharacters) {
      return false;
    }

    return !policy.allowedSpecialCharacters.includes(character);
  }),
  whitespace: countMatches(password, (character) => /\s/.test(character)),
});

const buildViolations = (
  metrics: PasswordMetrics,
  policy: NormalizedPasswordPolicy,
): PasswordPolicyViolation[] => {
  const violations: PasswordPolicyViolation[] = [];

  if (metrics.length < policy.minLength) {
    violations.push({
      code: "MIN_LENGTH",
      message: `Password must be at least ${policy.minLength} characters long.`,
      expected: policy.minLength,
      actual: metrics.length,
    });
  }

  if (metrics.length > policy.maxLength) {
    violations.push({
      code: "MAX_LENGTH",
      message: `Password must be at most ${policy.maxLength} characters long.`,
      expected: policy.maxLength,
      actual: metrics.length,
    });
  }

  if (metrics.lowercase < policy.minLowercase) {
    violations.push({
      code: "MIN_LOWERCASE",
      message: `Password must contain at least ${policy.minLowercase} lowercase characters.`,
      expected: policy.minLowercase,
      actual: metrics.lowercase,
    });
  }

  if (metrics.uppercase < policy.minUppercase) {
    violations.push({
      code: "MIN_UPPERCASE",
      message: `Password must contain at least ${policy.minUppercase} uppercase characters.`,
      expected: policy.minUppercase,
      actual: metrics.uppercase,
    });
  }

  if (metrics.numbers < policy.minNumbers) {
    violations.push({
      code: "MIN_NUMBERS",
      message: `Password must contain at least ${policy.minNumbers} numeric characters.`,
      expected: policy.minNumbers,
      actual: metrics.numbers,
    });
  }

  if (metrics.special < policy.minSpecial) {
    violations.push({
      code: "MIN_SPECIAL",
      message: `Password must contain at least ${policy.minSpecial} special characters.`,
      expected: policy.minSpecial,
      actual: metrics.special,
    });
  }

  if (metrics.disallowedSpecial > 0) {
    violations.push({
      code: "DISALLOWED_SPECIAL",
      message: `Password contains special characters that are not allowed. Allowed special characters: ${policy.allowedSpecialCharacters?.join(" ") ?? ""}.`,
      expected: 0,
      actual: metrics.disallowedSpecial,
    });
  }

  if (policy.forbidWhitespace && metrics.whitespace > 0) {
    violations.push({
      code: "WHITESPACE_NOT_ALLOWED",
      message: "Password must not contain whitespace.",
      expected: false,
      actual: metrics.whitespace,
    });
  }

  return violations;
};

export const normalizePasswordPolicy = (
  options: PasswordPolicyConfig<any> | NormalizedPasswordPolicy,
): NormalizedPasswordPolicy => {
  if (options !== true && (!options || typeof options !== "object")) {
    throw new PassauthPasswordPolicyConfigurationException(
      "Password policy options are required.",
    );
  }

  if (
    options !== true &&
    !("minLength" in options) &&
    Object.keys(options).length === 0
  ) {
    throw new PassauthPasswordPolicyConfigurationException(
      'Use `true` to enable the default password policy.',
    );
  }

  if (
    options !== true &&
    !("minLength" in options) &&
    options.rules &&
    Object.keys(options.rules).length === 0
  ) {
    throw new PassauthPasswordPolicyConfigurationException(
      '"rules" cannot be empty. Omit it or use `true` for the default password policy.',
    );
  }

  const rules: PasswordPolicyRules | NormalizedPasswordPolicy =
    options === true
      ? {}
      : "minLength" in options
        ? options
        : (options.rules ?? {});

  for (const field of INTEGER_FIELDS) {
    const value = rules[field];

    if (value === undefined) {
      continue;
    }

    if (field === "maxLength" && value === Number.POSITIVE_INFINITY) {
      continue;
    }

    if (!Number.isInteger(value) || value < 0) {
      throw new PassauthPasswordPolicyConfigurationException(
        `"${field}" must be a non-negative integer.`,
      );
    }
  }

  if (rules.maxLoginAttempts !== undefined && rules.maxLoginAttempts < 1) {
    throw new PassauthPasswordPolicyConfigurationException(
      '"maxLoginAttempts" must be greater than 0.',
    );
  }

  const policy: NormalizedPasswordPolicy = {
    minLength: rules.minLength ?? DEFAULT_PASSWORD_RULES.minLength,
    maxLength: rules.maxLength ?? DEFAULT_PASSWORD_RULES.maxLength,
    minLowercase: rules.minLowercase ?? DEFAULT_PASSWORD_RULES.minLowercase,
    minUppercase: rules.minUppercase ?? DEFAULT_PASSWORD_RULES.minUppercase,
    minNumbers: rules.minNumbers ?? DEFAULT_PASSWORD_RULES.minNumbers,
    minSpecial: rules.minSpecial ?? DEFAULT_PASSWORD_RULES.minSpecial,
    maxLoginAttempts:
      rules.maxLoginAttempts ?? DEFAULT_PASSWORD_RULES.maxLoginAttempts,
    forbidWhitespace:
      rules.forbidWhitespace ?? DEFAULT_PASSWORD_RULES.forbidWhitespace,
    allowedSpecialCharacters: normalizeAllowedSpecialCharacters(
      rules.allowedSpecialCharacters,
    ),
    specialCharacterPattern: cloneRegex(
      rules.specialCharacterPattern ?? DEFAULT_SPECIAL_CHARACTER_PATTERN,
    ),
  };

  if (policy.minLength > policy.maxLength) {
    throw new PassauthPasswordPolicyConfigurationException(
      '"minLength" cannot be greater than "maxLength".',
    );
  }

  return policy;
};

export const validatePasswordPolicy = (
  password: string,
  options: PasswordPolicyConfig<any> | NormalizedPasswordPolicy,
) => {
  const policy = normalizePasswordPolicy(options);
  const metrics = getPasswordMetrics(password, policy);
  const violations = buildViolations(metrics, policy);

  return {
    success: violations.length === 0,
    policy,
    metrics,
    violations,
  };
};

export const assertPasswordPolicy = (
  password: string,
  options: PasswordPolicyConfig<any> | NormalizedPasswordPolicy,
) => {
  const result = validatePasswordPolicy(password, options);

  if (!result.success) {
    throw new PassauthPasswordPolicyException(result);
  }
};
