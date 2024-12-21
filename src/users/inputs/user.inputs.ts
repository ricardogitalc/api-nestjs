import {
  IsString,
  IsEmail,
  MinLength,
  IsOptional,
  Matches,
  IsInt,
} from 'class-validator';

export class CreateUserInput {
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
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;

  @IsOptional()
  @IsString()
  profileUrl?: string;
}

export class UpdateUserInput {
  @IsInt()
  id: number;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName?: string;

  @IsOptional()
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password?: string;

  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;

  @IsOptional()
  @IsString()
  profileUrl?: string;
}

export class UpdateProfileInput {
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName?: string;

  @IsOptional()
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password?: string;

  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;

  @IsOptional()
  @IsString()
  profileUrl?: string;
}
