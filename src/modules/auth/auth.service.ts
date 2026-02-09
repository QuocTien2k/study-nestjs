import { Injectable } from '@nestjs/common';
import { AuthRequest } from './auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { UserWithoutPassword } from '../user/user.interface';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}

  //test potman
  async authenticate(request: AuthRequest): Promise<UserWithoutPassword> {
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
    const { password, ...safeUser } = user;
    console.log('Login success:', safeUser);
    return safeUser;
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
