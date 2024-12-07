import { InputType, Field, Int } from '@nestjs/graphql';
import {
  IsString,
  IsEmail,
  MinLength,
  IsOptional,
  Matches,
  IsInt,
} from 'class-validator';

@InputType()
export class CreateUserInput {
  @Field()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName: string;

  @Field()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName: string;

  @Field()
  @IsEmail({}, { message: 'Email inválido' })
  email: string;

  @Field()
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password: string;

  @Field()
  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;
}

@InputType()
export class UpdateUserInput {
  @Field(() => Int)
  @IsInt()
  id: number;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password?: string;

  @Field({ nullable: true })
  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;
}

@InputType()
export class UpdateProfileInput {
  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O nome deve ter no mínimo 2 caracteres' })
  firstName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'O sobrenome deve ter no mínimo 2 caracteres' })
  lastName?: string;

  @Field({ nullable: true })
  @IsOptional()
  @IsString()
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#@$!%*?&])[A-Za-z\d#@$!%*?&]{8,}$/,
    {
      message: 'Crie uma senha forte, por exemplo: #SuaSenha123',
    },
  )
  password?: string;

  @Field({ nullable: true })
  @IsOptional()
  @Matches(/^[1-9]{2}[9]{1}[0-9]{8}$/, {
    message: 'Número de WhatsApp deve estar no formato: 11999999999',
  })
  whatsapp?: string;
}