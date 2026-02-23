import { UserWithoutPassword } from '../user/user.interface';

export interface LoginResponse {
  user: UserWithoutPassword;
  accessToken: string;
  csrfToken: string;
  refreshToken?: string;
}

export interface AuthContext {
  ip?: string;
  userAgent?: string;
  deviceId: string;
}

export interface TokenPayload {
  sub: number;
  email: string;
  role: string;
  jti: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface SessionData {
  rtHash: string;
}
