import { IsString, IsEmail, IsOptional, Matches } from 'class-validator';

export class loginUserInput {
  @IsEmail()
  email: string;
  @IsString()
  password: string;
}

export class registerUserInput {
  @IsString()
  firstName: string;
  @IsString()
  lastName: string;
  @IsEmail()
  email: string;
  @IsString()
  password: string;
  @IsOptional()
  @Matches(/^\(\d{2}\)\s\d{5}-\d{4}$/)
  phone?: string;
}

export class refreshTokenInput {
  @IsString()
  refreshToken: string;
}

export class resetPwdSentInput {
  @IsEmail()
  email: string;
}

export class resetPwdConfInput {
  @IsString()
  resetToken: string;
  @IsString()
  newPassword: string;
}
