import { UserWithoutPassword } from '../user/user.interface';

export interface LoginResponse {
  user: UserWithoutPassword;
  accessToken: string;
  csrfToken: string;
}
