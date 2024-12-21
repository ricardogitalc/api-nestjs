import {
  IsEmail,
  IsString,
  MinLength,
  IsOptional,
  Matches,
} from 'class-validator';

export class loginUserInput {
  @IsEmail({}, { message: 'Email inválido' })
  email: string;
  @IsString()
  password: string;
}

export class registerUserInput {
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName: string;
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName: string;
  @IsEmail({}, { message: 'Email inválido' })
  email: string;
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password: string;
  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'O número deve estar no formato: 11999999999',
  })
  phone?: string;
}

export class refreshTokenInput {
  @IsString()
  refreshToken: string;
}

export class resetPwdSentInput {
  @IsEmail({}, { message: 'Email inválido' })
  email: string;
}

export class resetPwdConfInput {
  @IsString()
  resetToken: string;
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  newPassword: string;
}
