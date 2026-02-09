import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthRequest {
  @IsEmail({}, { message: 'IS_EMAIL' })
  @IsNotEmpty({ message: 'REQUIRED' })
  email: string;

  @IsString({ message: 'IS_STRING' })
  @MinLength(6, { message: 'MIN_LENGTH' })
  @IsNotEmpty({ message: 'REQUIRED' })
  password: string;
}
