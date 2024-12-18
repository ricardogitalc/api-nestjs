import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { CONFIG_MESSAGES, JWT_TIMES } from 'src/config/config';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { loginUserInput, registerUserInput } from './inputs/auth.inputs';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private configService: ConfigService,
  ) {}

  private generateKey(secret: string): Uint8Array {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(secret);
    const buffer = new Uint8Array(32);
    buffer.set(keyBytes.slice(0, 32));

    return buffer;
  }

  private async verifyResetToken(resetToken: string) {
    const secret = this.configService.get('JWT_SECRET_KEY');
    const key = this.generateKey(secret);
    return jose.jwtDecrypt(resetToken, key);
  }

  async generateJwtTokens(user: any) {
    const secret = this.configService.get('JWT_SECRET_KEY');
    const key = this.generateKey(secret);
    return await new jose.EncryptJWT({
      sub: user.id,
      role: user.role,
      provider: user.provider,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      whatsapp: user.whatsapp,
      verified: user.verified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setExpirationTime(JWT_TIMES.ACCESS_TOKEN)
      .encrypt(key);
  }

  async generateRefreshTokens(id: number) {
    const secret = this.configService.get('REFRESH_SECRET_KEY');
    const key = this.generateKey(secret);
    return await new jose.EncryptJWT({
      sub: id.toString(),
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setExpirationTime(JWT_TIMES.REFRESH_TOKEN)
      .encrypt(key);
  }

  async validateUser(email: string) {
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    return user;
  }

  async login(loginUserInput: loginUserInput) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { email: loginUserInput.email },
      });

      if (!user) {
        throw new UnauthorizedException(CONFIG_MESSAGES.invalidEmail);
      }

      if (!user.verified) {
        throw new UnauthorizedException(CONFIG_MESSAGES.userNotVerified);
      }

      if (user.provider === 'GOOGLE') {
        throw new UnauthorizedException('Sua conta foi criada com o Google');
      }

      const isPasswordValid = await bcrypt.compare(
        loginUserInput.password,
        user.password,
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException(CONFIG_MESSAGES.invalidPassword);
      }

      const { password: _, ...result } = user;
      const accessToken = await this.generateJwtTokens(result);
      const refreshToken = await this.generateRefreshTokens(result.id);

      return {
        message: CONFIG_MESSAGES.userLogged,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw error;
    }
  }

  async register(registerUserInput: registerUserInput) {
    try {
      const { email, password } = registerUserInput;

      const user = await this.prismaService.user.findUnique({
        where: { email },
      });

      if (user && user.verified) {
        throw new UnauthorizedException(CONFIG_MESSAGES.userAllReady);
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      let createdOrUpdatedUser;
      if (user && !user.verified) {
        createdOrUpdatedUser = await this.prismaService.user.update({
          where: { email },
          data: {
            ...registerUserInput,
            password: hashedPassword,
          },
        });
      } else {
        createdOrUpdatedUser = await this.prismaService.user.create({
          data: {
            ...registerUserInput,
            password: hashedPassword,
          },
        });
      }

      const verificationToken = await this.generateJwtTokens({
        id: createdOrUpdatedUser.id,
        email: createdOrUpdatedUser.email,
      });

      return {
        message: CONFIG_MESSAGES.userCreated,
        verificationToken,
      };
    } catch (error) {
      throw error;
    }
  }

  async verifyRegister(verifyToken: string) {
    try {
      const { payload } = await this.verifyResetToken(verifyToken);
      const userId = Number(payload.sub);

      const user = await this.prismaService.user.update({
        where: { id: userId },
        data: { verified: true },
      });

      const accessToken = await this.generateJwtTokens(user);
      const refreshToken = await this.generateRefreshTokens(user.id);

      return {
        message: CONFIG_MESSAGES.userVerified,
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException(CONFIG_MESSAGES.tokenInvalid);
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      const secret = this.configService.get('REFRESH_SECRET_KEY');
      const key = this.generateKey(secret);

      try {
        const { payload } = await jose.jwtDecrypt(refreshToken, key);
        const userId = Number(payload.sub);

        const user = await this.prismaService.user.findUnique({
          where: { id: userId },
        });

        if (!user) {
          throw new UnauthorizedException('Usuário não encontrado');
        }

        const accessToken = await this.generateJwtTokens(user);
        const newRefreshToken = await this.generateRefreshTokens(user.id);

        return {
          message: 'Token atualizado com sucesso',
          accessToken,
          refreshToken: newRefreshToken,
        };
      } catch (error) {
        throw new UnauthorizedException('Refresh token expirado ou inválido');
      }
    } catch (error) {
      throw error;
    }
  }

  async resetPwdSent(email: string) {
    const user = await this.prismaService.user.findUnique({ where: { email } });

    if (!user) {
      throw new NotFoundException(CONFIG_MESSAGES.userNotFound);
    }

    if (!user.verified) {
      throw new UnauthorizedException(CONFIG_MESSAGES.userNotVerified);
    }

    const resetToken = await this.generateJwtTokens({
      id: user.id,
    });

    // Envio de email.

    return { message: CONFIG_MESSAGES.resetPasswordLinkSent, resetToken };
  }

  async resetPwdConf(resetToken: string, newPassword: string) {
    try {
      const { payload } = await this.verifyResetToken(resetToken);

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      const userId = Number(payload.sub);

      await this.prismaService.user.update({
        where: { id: userId },
        data: { password: hashedPassword, provider: 'CREDENTIALS' },
      });

      return { message: CONFIG_MESSAGES.resetPasswordReseted };
    } catch (error) {
      throw new UnauthorizedException(CONFIG_MESSAGES.tokenInvalid);
    }
  }

  async googleLogin(profile: any) {
    try {
      let user = await this.prismaService.user.findUnique({
        where: { email: profile.email },
      });

      if (!user) {
        user = await this.prismaService.user.create({
          data: {
            email: profile.email,
            firstName: profile.firstName,
            lastName: profile.lastName,
            provider: 'GOOGLE',
            verified: true,
          },
        });
      } else {
        const userId = user.id;

        await this.prismaService.user.update({
          where: { id: userId },
          data: { provider: 'GOOGLE' },
        });
      }

      const accessToken = await this.generateJwtTokens(user);
      const refreshToken = await this.generateRefreshTokens(user.id);

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException('Erro na autenticação do Google');
    }
  }
}
