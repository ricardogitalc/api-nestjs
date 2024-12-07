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
import { createHash } from 'crypto';
import { loginUserInput, registerUserInput } from './inputs/auth.inputs';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private configService: ConfigService,
  ) {}

  private async verifyResetToken(resetToken: string) {
    const secret = this.configService.get('JWT_SECRET_KEY');
    const key = createHash('sha256').update(secret).digest();
    return jose.jwtDecrypt(resetToken, key);
  }

  async generateJwtTokens(user: any) {
    const secret = this.configService.get('JWT_SECRET_KEY');
    const key = createHash('sha256').update(secret).digest();
    return await new jose.EncryptJWT({
      sub: user.id,
      email: user.email,
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setExpirationTime(JWT_TIMES.ACCESS_TOKEN)
      .encrypt(key);
  }

  async generateRefreshTokens(user: any) {
    const secret = this.configService.get('REFRESH_SECRET_KEY');
    const key = createHash('sha256').update(secret).digest();
    return await new jose.EncryptJWT({
      sub: user.id,
      email: user.email,
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setExpirationTime(JWT_TIMES.REFRESH_TOKEN)
      .encrypt(key);
  }

  async validateUser(email: string, password: string) {
    const user = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException(CONFIG_MESSAGES.invalidEmail);
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException(CONFIG_MESSAGES.invalidPassword);
    }

    if (!user.verified) {
      throw new UnauthorizedException(CONFIG_MESSAGES.userNotVerified);
    }

    const { password: _, ...result } = user;
    return result;
  }

  async login(loginUserInput: loginUserInput) {
    try {
      const user = await this.validateUser(
        loginUserInput.email,
        loginUserInput.password,
      );

      const isGoogleProvider = await this.prismaService.user.findFirst({
        where: {
          provider: 'GOOGLE',
          email: loginUserInput.email,
        },
      });

      if (isGoogleProvider) {
        throw new UnauthorizedException(
          'Sua conta foi criada com o Google, faça login com o Google',
        );
      }

      return {
        message: CONFIG_MESSAGES.userLogged,
        accessToken: await this.generateJwtTokens(user),
        refreshToken: await this.generateRefreshTokens(user),
      };
    } catch (error) {
      throw error;
    }
  }

  async register(registerUserInput: registerUserInput) {
    const { email, password } = registerUserInput;

    const existingUser = await this.prismaService.user.findUnique({
      where: { email },
    });

    if (existingUser && existingUser.verified) {
      throw new UnauthorizedException(CONFIG_MESSAGES.userAllReady);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    let user;

    if (existingUser) {
      user = await this.prismaService.user.update({
        where: { email },
        data: {
          ...registerUserInput,
          password: hashedPassword,
          verified: false,
        },
      });
    } else {
      user = await this.prismaService.user.create({
        data: {
          ...registerUserInput,
          password: hashedPassword,
          verified: false,
        },
      });
    }

    const verificationToken = await this.generateJwtTokens({
      id: user.id,
      email: user.email,
    });

    return {
      message: CONFIG_MESSAGES.userCreated,
      verificationToken,
    };
  }

  async verifyUser(verifyToken: string) {
    try {
      const secret = this.configService.get('JWT_SECRET_KEY');
      const key = createHash('sha256').update(secret).digest();
      const { payload } = await jose.jwtDecrypt(verifyToken, key);
      const userId = Number(payload.sub);

      const user = await this.prismaService.user.update({
        where: { id: userId },
        data: { verified: true },
      });

      const accessToken = await this.generateJwtTokens(user);
      const refreshToken = await this.generateRefreshTokens(user);

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
      const key = createHash('sha256').update(secret).digest();
      const { payload } = await jose.jwtDecrypt(refreshToken, key);
      const userId = Number(payload.sub);

      const user = await this.prismaService.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new UnauthorizedException(CONFIG_MESSAGES.userNotFound);
      }

      const accessToken = await this.generateJwtTokens(user);

      return {
        message: CONFIG_MESSAGES.tokenRefreshed,
        accessToken,
      };
    } catch {
      throw new UnauthorizedException(CONFIG_MESSAGES.tokenInvalid);
    }
  }

  async resetPwdSent(email: string) {
    const user = await this.prismaService.user.findUnique({ where: { email } });

    if (!user) {
      throw new NotFoundException(CONFIG_MESSAGES.userNotFound);
    }

    const resetToken = await this.generateJwtTokens({
      id: user.id,
      email: user.email,
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
        data: { password: hashedPassword },
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
      }

      return {
        accessToken: await this.generateJwtTokens(user),
        refreshToken: await this.generateRefreshTokens(user),
      };
    } catch (error) {
      throw new UnauthorizedException('Erro na autenticação do Google');
    }
  }
}
