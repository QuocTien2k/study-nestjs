import { Injectable } from '@nestjs/common';
import { AuthRequest } from './auth.dto';

@Injectable()
export class AuthService {
  authenticate(request: AuthRequest): string {
    console.log('Đã nhập request: ', request);
    return 'Attemp trong Auth Service!';
  }
}
