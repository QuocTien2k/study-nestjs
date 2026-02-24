import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthRequest } from './auth.dto';
import { ValidationPipe } from 'src/pipes/validation.pipe';
import { JwtAuthGuard } from 'src/common/guards/jwt-auth.guard';
import type { Request } from 'express';
import { RefreshRequest } from './refresh.dto';
import { RefreshAuthGuard } from 'src/common/guards/refresh-auth.guard';

// import { AuthGuard } from '@nestjs/passport';

@Controller('v1/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  login(@Body(new ValidationPipe()) body: AuthRequest, @Req() req: Request) {
    //validate và body có dữ liệu
    return this.authService.authenticate(body, req); //truyền liệu vào service
  }

  @UseGuards(JwtAuthGuard)
  @Get('/profile')
  getProfile() {
    return 'Protected route';
  }

  @UseGuards(RefreshAuthGuard)
  @Post('/refresh')
  refresh(
    @Body(new ValidationPipe()) body: RefreshRequest,
    @Req() req: Request,
  ) {
    return this.authService.refreshSession(body.refreshToken, req);
  }

  @UseGuards(JwtAuthGuard)
  @Post('/logout')
  logout(@Req() req: Request) {
    const user = req.user as any;

    return this.authService.logout(req, user.id);
  }
}
