import { AuthHandler } from "./auth";
import { PassauthMissingConfigurationException } from "./exceptions";
import type { PassauthConfiguration, User } from "./types";

export const Passauth = <T extends User>(options: PassauthConfiguration<T>) => {
  if (!options.secretKey) {
    throw new PassauthMissingConfigurationException("secretKey");
  }

  if (!options.repo) {
    throw new PassauthMissingConfigurationException("repo");
  }

  const handler = new AuthHandler<T>(options, options.repo);

  return { handler };
};
