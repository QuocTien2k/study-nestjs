import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import type { Request } from 'express';
import { createHash } from 'crypto';

@Injectable()
export class AccessJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-access',
) {
  constructor(
    config: ConfigService,
    @Inject(CACHE_MANAGER) private cache: Cache,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('ACCESS_TOKEN_SECRET')!,
      passReqToCallback: true, //cho phép lấy Request
    });
  }
  private createDeviceId(req: Request): string {
    const ip = req.ip;
    const userAgent = req.headers['user-agent'] ?? '';

    const raw = `${ip}:${userAgent}`;

    return createHash('sha256').update(raw).digest('hex');
  }

  async validate(req: Request, payload: any) {
    const deviceId = this.createDeviceId(req);

    const sessionKey = `session:${payload.sub}:${deviceId}`;

    const session = await this.cache.get<{ jti: string }>(sessionKey);

    if (!session) {
      throw new UnauthorizedException('Session expired');
    }

    if (session.jti !== payload.jti) {
      throw new UnauthorizedException('Invalid session');
    }
    // payload chính là data đã sign trong AuthService
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }
}
