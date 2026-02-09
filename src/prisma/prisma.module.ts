import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Global() // 👈 rất quan trọng
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
