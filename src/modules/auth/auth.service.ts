import { Inject, Injectable } from '@nestjs/common';
import { AuthRequest } from './auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {
  AuthContext,
  LoginResponse,
  SessionData,
  TokenPair,
  TokenPayload,
} from './auth.interface';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { UserWithoutPassword } from '../user/user.interface';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import type { Request } from 'express';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    @Inject(CACHE_MANAGER) private cache: Cache,
  ) {}

  //test potman
  async authenticate(
    request: AuthRequest,
    req: Request,
  ): Promise<LoginResponse> {
    // 1️⃣ context
    const context = this.createAuthContext(req);
    // console.log('DEVICE ID:', context.deviceId);

    // 2️⃣ validate
    const user = await this.validateUser(request.email, request.password);

    // 3️⃣ remove old device session
    await this.cache.del(`session:${user.id}:${context.deviceId}`);

    // 4️⃣ payload
    const payload = this.createTokenPayload(user);

    // 5️⃣ tokens
    const tokens = this.generateTokens(payload);

    // 6️⃣ csrf
    const csrfToken = this.generateCsrfToken();

    // 7️⃣ save session (DEVICE BASED)
    const hashedRt = await bcrypt.hash(tokens.refreshToken, 10);

    await this.saveDeviceSession(user.id, context.deviceId, payload.jti, {
      rtHash: hashedRt,
    });

    return {
      user,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      csrfToken,
    };
  }

  /* ============== VALIDATE USER ============== */
  async validateUser(
    email: string,
    password: string,
  ): Promise<UserWithoutPassword> {
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Email không tồn tại');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    const { password: _, ...safeUser } = user;
    return safeUser;
  }

  /* ============== TOKEN PAYLOAD ============== */
  private createTokenPayload(user: UserWithoutPassword): TokenPayload {
    return {
      sub: user.id,
      email: user.email,
      role: user.role,
      jti: randomUUID(),
    };
  }

  /* ============== GENERATE TOKENS ============== */
  private generateTokens(payload: TokenPayload): TokenPair {
    return {
      accessToken: this.jwtService.sign(payload, {
        secret: this.configService.get('ACCESS_TOKEN_SECRET'),
        expiresIn: this.configService.get('ACCESS_TOKEN_EXPIRES'),
      }),

      refreshToken: this.jwtService.sign(payload, {
        secret: this.configService.get('REFRESH_TOKEN_SECRET'),
        expiresIn: this.configService.get('REFRESH_TOKEN_EXPIRES'),
      }),
    };
  }

  /* ============== CSRF TOKEN ============== */
  private generateCsrfToken(): string {
    return randomBytes(32).toString('hex');
  }

  /* ============== REDIS SESSION ============== */
  private async saveDeviceSession(
    userId: number,
    deviceId: string,
    jti: string,
    session: SessionData,
  ) {
    await this.cache.set(
      `session:${userId}:${deviceId}`,
      {
        ...session,
        jti,
      },
      1000 * 60 * 60 * 24 * 7,
    );
  }

  /* ============== CREATE AUTH CONTEXT ============== */
  private createAuthContext(req: Request): AuthContext {
    const ip = req.ip;
    const userAgent = req.headers['user-agent'] ?? '';

    const raw = `${ip}:${userAgent}`;

    const deviceId = createHash('sha256').update(raw).digest('hex');

    return {
      ip,
      userAgent,
      deviceId,
    };
  }

  /* ============== REFRESH TOKEN ============== */
  async refreshSession(refreshToken: string, req: Request): Promise<TokenPair> {
    // 1️⃣ verify refresh token
    let payload: TokenPayload;

    try {
      payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // 2️⃣ rebuild device context
    const context = this.createAuthContext(req);

    // 3️⃣ load redis session
    const sessionKey = `session:${payload.sub}:${context.deviceId}`;

    const session = await this.cache.get<SessionData & { jti: string }>(
      sessionKey,
    );

    if (!session) {
      throw new UnauthorizedException('Session not found');
    }

    // 4️⃣ check jti (ANTI TOKEN REUSE)
    if (session.jti !== payload.jti) {
      await this.cache.del(sessionKey);
      throw new UnauthorizedException('Token reuse detected');
    }

    // 5️⃣ compare refresh token hash
    const match = await bcrypt.compare(refreshToken, session.rtHash);

    if (!match) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // 6️⃣ ROTATE TOKEN (VERY IMPORTANT)
    const newPayload: TokenPayload = {
      sub: payload.sub,
      email: payload.email,
      role: payload.role,
      jti: randomUUID(),
    };

    const tokens = this.generateTokens(newPayload);

    const hashedRt = await bcrypt.hash(tokens.refreshToken, 10);

    // 7️⃣ update redis session
    await this.saveDeviceSession(
      payload.sub,
      context.deviceId,
      newPayload.jti,
      { rtHash: hashedRt },
    );

    return tokens;
  }
}
