import type { TemplateTypes } from "../email.enum";

export type SendEmailArgs = {
  senderName: string;
  from: string;
  to: string[];
  subject: string;
  text: string;
  html: string;
};

export interface EmailClient {
  send(emailData: SendEmailArgs): Promise<void>;
}

export type TemplateArgs = {
  email: string;
  link: string;
};

export type GetEmailTemplate = (params: TemplateArgs) => {
  text: string;
  html: string;
};

export type ConfirmEmailParams = {
  linkParams: Record<string, unknown>;
};

export type ResetPasswordEmailParams = {
  linkParams: Record<string, unknown>;
};

type EmailTemplatesOptions = {
  [TemplateTypes.CONFIRM_EMAIL]?: GetEmailTemplate;
  [TemplateTypes.RESET_PASSWORD]?: GetEmailTemplate;
};

type OverrideEmailArgs = Omit<Partial<SendEmailArgs>, "text" | "html" | "to">;

export type EmailHandlerOptions = {
  senderName: string;
  senderEmail: string;
  client: EmailClient;
  emailConfig?: {
    [TemplateTypes.CONFIRM_EMAIL]?: {
      email?: OverrideEmailArgs;
      linkExpirationMs?: number;
    };
    [TemplateTypes.RESET_PASSWORD]?: {
      email?: OverrideEmailArgs;
      linkExpirationMs?: number;
    };
  };
  templates?: EmailTemplatesOptions;
  services: {
    createResetPasswordLink(
      email: string,
      token: string,
      linkParams?: Record<string, unknown>,
    ): Promise<string>;
    createConfirmEmailLink(email: string, token: string, linkParams?: Record<string, unknown>): Promise<string>;
  };
  repo: {
    confirmEmail(email: string, emailParams?: ConfirmEmailParams): Promise<boolean>;
    resetPassword(
      email: string,
      password: string,
      emailParams?: ResetPasswordEmailParams,
    ): Promise<boolean>;
  };
};
