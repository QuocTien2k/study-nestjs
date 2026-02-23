import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthRequest } from './auth.dto';
import { ValidationPipe } from 'src/pipes/validation.pipe';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';

// import { AuthGuard } from '@nestjs/passport';

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // @Post('/login')
  // login(): string {
  //   return this.authService.attempt();
  // }
  // @UseGuards(AuthGuard('local'))
  @Post('/login')
  login(@Body(new ValidationPipe()) body: AuthRequest) {
    //validate và body có dữ liệu
    return this.authService.authenticate(body); //truyền liệu vào service
  }

  @UseGuards(JwtAuthGuard)
  @Get('/profile')
  getProfile() {
    return 'Protected route';
  }
}
