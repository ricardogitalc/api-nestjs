import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { CONFIG_MESSAGES } from 'src/config/config';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { Reflector } from '@nestjs/core';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private configService: ConfigService,
    private reflector: Reflector,
  ) {
    super();
  }

  private generateKey(secret: string): Uint8Array {
    const encoder = new TextEncoder();
    const keyBytes = encoder.encode(secret);
    const buffer = new Uint8Array(32);
    buffer.set(keyBytes.slice(0, 32));
    return buffer;
  }

  protected async validateToken(token: string) {
    try {
      const secret = this.configService.get<string>('JWT_SECRET_KEY');
      const key = this.generateKey(secret);
      return await jose.jwtDecrypt(token, key);
    } catch (error) {
      throw new UnauthorizedException('Token inválido ou expirado');
    }
  }

  getRequest(context: ExecutionContext) {
    return context.switchToHttp().getRequest();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = this.getRequest(context);
    const authHeader = request.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException(CONFIG_MESSAGES.tokenNotSent);
    }

    const token = authHeader.split(' ')[1];
    const { payload } = await this.validateToken(token);

    request.user = {
      sub: payload.sub,
      email: payload.email,
    };

    return true;
  }
}
