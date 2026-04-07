import { describe, expect, test } from "@jest/globals";
import {
  PassauthPasswordPolicyConfigurationException,
  PassauthPasswordPolicyException,
  assertPasswordPolicy,
  normalizePasswordPolicy,
  validatePasswordPolicy,
} from "../../src";

describe("Passauth password policy utils", () => {
  test("uses the default rule values when rules are not provided", () => {
    const result = validatePasswordPolicy("any password", {});

    expect(result.success).toBe(false);
    expect(result.violations.map((violation) => violation.code)).toEqual([
      "MIN_UPPERCASE",
      "MIN_NUMBERS",
      "MIN_SPECIAL",
      "WHITESPACE_NOT_ALLOWED",
    ]);
    expect(result.policy).toEqual({
      minLength: 6,
      maxLength: 12,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSpecial: 1,
      maxLoginAttempts: 3,
      forbidWhitespace: true,
      allowedSpecialCharacters: undefined,
      specialCharacterPattern: /[^A-Za-z0-9\s]/,
    });
  });

  test("validates password metrics and violations", () => {
    const result = validatePasswordPolicy("weak", {
      rules: {
        minLength: 8,
        minUppercase: 1,
        minNumbers: 1,
        minSpecial: 1,
      },
    });

    expect(result.success).toBe(false);
    expect(result.metrics).toEqual({
      length: 4,
      lowercase: 4,
      uppercase: 0,
      numbers: 0,
      special: 0,
      disallowedSpecial: 0,
      whitespace: 0,
    });
    expect(result.violations.map((violation) => violation.code)).toEqual([
      "MIN_LENGTH",
      "MIN_UPPERCASE",
      "MIN_NUMBERS",
      "MIN_SPECIAL",
    ]);
  });

  test("throws a typed exception when the password is invalid", () => {
    expect(() =>
      assertPasswordPolicy("NoSpaces1", {
        rules: {
          minSpecial: 1,
          forbidWhitespace: true,
        },
      }),
    ).toThrow(PassauthPasswordPolicyException);
  });

  test("supports an allow-list of special characters", () => {
    const result = validatePasswordPolicy("StrongPass1*", {
      rules: {
        minSpecial: 1,
        allowedSpecialCharacters: "!@#",
      },
    });

    expect(result.success).toBe(false);
    expect(result.metrics.special).toBe(0);
    expect(result.metrics.disallowedSpecial).toBe(1);
    expect(result.violations.map((violation) => violation.code)).toEqual([
      "MIN_SPECIAL",
      "DISALLOWED_SPECIAL",
    ]);
  });

  test("accepts passwords that use only configured special characters", () => {
    const result = validatePasswordPolicy("StrongPass1!", {
      rules: {
        minSpecial: 1,
        allowedSpecialCharacters: ["!", "@", "#"],
      },
    });

    expect(result.success).toBe(true);
    expect(result.metrics.special).toBe(1);
    expect(result.metrics.disallowedSpecial).toBe(0);
  });

  test("rejects invalid password policy configurations", () => {
    expect(() =>
      normalizePasswordPolicy({
        rules: {
          allowedSpecialCharacters: ["A"],
        },
      }),
    ).toThrow(PassauthPasswordPolicyConfigurationException);

    expect(() =>
      normalizePasswordPolicy({
        rules: {
          minLength: 12,
          maxLength: 8,
        },
      }),
    ).toThrow(PassauthPasswordPolicyConfigurationException);

    expect(() =>
      normalizePasswordPolicy({
        rules: {
          maxLoginAttempts: 0,
        },
      }),
    ).toThrow(PassauthPasswordPolicyConfigurationException);
  });
});
