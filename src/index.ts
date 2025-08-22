import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import type { PassauthConfiguration, User } from "./auth/auth.types";
import { EmailPlugin } from "./email/email.handler";

export const Passauth = <T extends User>(options: PassauthConfiguration<T>) => {
  if (!options.secretKey) {
    throw new PassauthMissingConfigurationException("secretKey");
  }

  if (!options.repo) {
    throw new PassauthMissingConfigurationException("repo");
  }

  if (options.requireEmailConfirmation && !options.emailPlugin) {
    throw new PassauthMissingConfigurationException("emailPlugin");
  }

  const emailPlugin = options.emailPlugin && EmailPlugin(options.emailPlugin);
  const handler = new AuthHandler<T>(options, options.repo, emailPlugin);

  return { handler };
};
