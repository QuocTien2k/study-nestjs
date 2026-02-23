import { Inject, Injectable } from '@nestjs/common';
import { AuthRequest } from './auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { LoginResponse } from './auth.interface';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, randomUUID } from 'crypto';
import { UserWithoutPassword } from '../user/user.interface';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    @Inject(CACHE_MANAGER) private cache: Cache,
  ) {}

  //test potman
  async authenticate(request: AuthRequest): Promise<LoginResponse> {
    const user = await this.prisma.user.findUnique({
      where: { email: request.email },
    });
    if (!user) {
      throw new UnauthorizedException('Email không tồn tại!');
    }

    const isPasswordValid = await bcrypt.compare(
      request.password,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Email hoặc mật khẩu không đúng');
    }

    const { password, ...safeUser } = user; //ko trả về password và refreshToken
    //console.log('Login success:', safeUser);

    const jti = randomUUID();

    // 🔐 Tạo payload
    const payload = {
      sub: safeUser.id,
      email: safeUser.email,
      role: safeUser.role,
      jti,
    };

    // 🎟️ Access Token
    const accessToken = this.jwtService.sign(payload, {
      expiresIn: '15m',
    });

    // ✅ refresh token
    const refreshToken = this.jwtService.sign(payload, {
      expiresIn: '7d',
    });

    // hash refresh token
    const hashedRt = await bcrypt.hash(refreshToken, 10);

    // 🛡️ CSRF Token (tạm thời random string)
    const csrfToken = randomBytes(32).toString('hex');

    // 🔥 save Redis session
    await (this.cache as any).set(
      `session:${safeUser.id}:${jti}`,
      { rtHash: hashedRt },
      1000 * 60 * 60 * 24 * 7,
    );
    // console.log(this.cache);

    return {
      user: safeUser,
      accessToken,
      csrfToken,
    };
  }

  // ✅ Dùng cho LocalStrategy
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
}
