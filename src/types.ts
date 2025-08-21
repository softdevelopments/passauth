export type ID = string | number;

export type User = {
  id: ID;
  email: string;
  password: string;
};

export type RegisterParams = {
  email: string;
  password: string;
};

export type LoginParams = {
  email: string;
  password: string;
};

export interface AuthRepo<T extends User> {
  getUser(email: string): Promise<T | null>;
  createUser(params: RegisterParams): Promise<T>;
  getRefreshToken(userId: ID): Promise<string | null | undefined>;
  saveRefreshToken(userId: ID, refreshToken: string): Promise<void>;
  invalidateRefreshToken(userId: ID): Promise<void>;
}

export type HandlerOptions = {
  secretKey: string;
  saltingRounds: number;
  accessTokenExpirationMs: number;
  refreshTokenExpirationMs: number;
};

export type PassauthConfiguration<T extends User> = HandlerOptions & {
  repo: AuthRepo<T>;
};

export type TokenPayload = {
  id: ID;
  tokenId: string;
};
