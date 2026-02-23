import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './jwt.strategy';
import { CommonModule } from 'src/common/common.module';

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      secret: 'super_secret_key', //sau này dùng .env
      signOptions: { expiresIn: '15m' },
    }),
    CommonModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, LocalStrategy, JwtStrategy],
  exports: [PassportModule, JwtModule],
})
export class AuthModule {}
