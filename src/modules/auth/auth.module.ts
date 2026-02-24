import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { JwtModule, JwtModuleOptions } from '@nestjs/jwt';
import { AccessJwtStrategy } from './strategies/access-jwt.strategy';
import { CommonModule } from 'src/common/common.module';
import { ConfigService } from '@nestjs/config';
import { RefreshJwtStrategy } from './strategies/refresh-jwt.strategy';
import { RedisProvider } from './redis.provider';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService): JwtModuleOptions => ({
        secret: config.get<string>('ACCESS_TOKEN_SECRET')!,
        signOptions: {
          expiresIn: config.get<string>('ACCESS_TOKEN_EXPIRES')! as any,
        },
      }),
    }),
    CommonModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    LocalStrategy,
    AccessJwtStrategy,
    RefreshJwtStrategy,
    RedisProvider,
  ],
  exports: [PassportModule, JwtModule],
})
export class AuthModule {}
