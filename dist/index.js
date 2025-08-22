import { AuthHandler } from "./auth/auth.handler";
import { PassauthMissingConfigurationException } from "./auth/auth.exceptions";
import { EmailPlugin } from "./email/email.handler";
export const Passauth = (options) => {
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
    const handler = new AuthHandler(options, options.repo, emailPlugin);
    return { handler };
};
//# sourceMappingURL=index.js.map