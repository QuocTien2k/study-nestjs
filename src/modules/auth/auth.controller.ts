import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthRequest } from './auth.dto';
import { ValidationPipe } from 'src/pipes/validation.pipe';

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @Post('/login')
  // login(): string {
  //   return this.authService.attempt();
  // }

  @Post('/login')
  login(@Body(new ValidationPipe()) body: AuthRequest) {
    // debug xem body đã qua validator chưa
    //return body;
    try {
      return this.authService.authenticate(request);
    } catch (error) {
      console.error('Error: ', error);
    }
  }
}
