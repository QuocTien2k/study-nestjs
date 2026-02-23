import { Module } from '@nestjs/common';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  providers: [JwtAuthGuard], //cho container
  exports: [JwtAuthGuard], // cho các module khác
})
export class CommonModule {}
