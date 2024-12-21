import {
  IsString,
  IsEmail,
  MinLength,
  IsOptional,
  Matches,
  IsInt,
  Length,
  MaxLength,
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
    message: 'O número deve estar no formato: 11999999999',
  })
  phone: string;
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
    message: 'O número deve estar no formato: 11999999999',
  })
  phone?: string;

  @IsOptional()
  @IsString()
  profileUrl?: string;
}

export class UpdateProfileInput {
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  @MaxLength(50, { message: 'O nome deve ter no máximo 100 caracteres' })
  firstName?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  @MaxLength(50, { message: 'O sobrenome deve ter no máximo 100 caracteres' })
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
  @IsString()
  profileUrl?: string;

  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'O número deve estar no formato: 11999999999',
  })
  phone?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{3}\.\d{3}\.\d{3}\-\d{2}$/, {
    message: 'CPF inválido. Use o formato: 123.456.789-00',
  })
  cpf?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{5}-\d{3}$/, {
    message: 'CEP inválido. Use o formato: 12345-678',
  })
  zipCode?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'A cidade deve ter no mínimo 2 caracteres' })
  @MaxLength(100, { message: 'A cidade deve ter no máximo 100 caracteres' })
  city?: string;

  @IsOptional()
  @IsString()
  @Length(2, 2, { message: 'O estado deve ter 2 caracteres (ex: SP, RJ, MG)' })
  state?: string;

  @IsOptional()
  @IsString()
  @MinLength(3, { message: 'O endereço deve ter no mínimo 3 caracteres' })
  @MaxLength(150, { message: 'O endereço deve ter no máximo 150 caracteres' })
  anddress?: string;

  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O bairro deve ter no mínimo 2 caracteres' })
  @MaxLength(100, { message: 'O bairro deve ter no máximo 100 caracteres' })
  district?: string;

  @IsOptional()
  @IsString()
  @MaxLength(10, { message: 'O número deve ter no máximo 10 caracteres' })
  number?: string;
}
