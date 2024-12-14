import {
  Controller,
  Get,
  Post,
  Body,
  Logger,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Public } from 'src/common/decorators/public.decorator';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { CONFIG_MESSAGES } from 'src/config/config';
import {
  loginUserInput,
  registerUserInput,
  refreshTokenInput,
  resetPwdSentInput,
  resetPwdConfInput,
} from './inputs/auth.inputs';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly logger: Logger,
  ) {}

  @Public()
  @Post('login')
  async login(@Body() loginUserInput: loginUserInput) {
    return this.authService.login(loginUserInput);
  }

  @Public()
  @Post('register')
  async register(@Body() registerUserInput: registerUserInput) {
    return this.authService.register(registerUserInput);
  }

  @Public()
  @Post('verify')
  async verifyRegister(@Body('verificationToken') verificationToken: string) {
    return this.authService.verifyRegister(verificationToken);
  }

  @Public()
  @Post('refresh')
  async refreshToken(@Body() refreshTokenInput: refreshTokenInput) {
    return this.authService.refreshToken(refreshTokenInput.refreshToken);
  }

  @Public()
  @Post('reset-password')
  async resetPwdSent(@Body() resetPwdSentInput: resetPwdSentInput) {
    return this.authService.resetPwdSent(resetPwdSentInput.email);
  }

  @Public()
  @Post('reset-password/confirm')
  async resetPwdConf(@Body() resetPwdConfInput: resetPwdConfInput) {
    return this.authService.resetPwdConf(
      resetPwdConfInput.resetToken,
      resetPwdConfInput.newPassword,
    );
  }

  @Public()
  @Get('google')
  @UseGuards(AuthGuard('google'))
  async googleAuth() {}

  @Public()
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req) {
    const { accessToken, refreshToken } = await this.authService.googleLogin(
      req.user,
    );

    return {
      message: CONFIG_MESSAGES.userLogged,
      accessToken,
      refreshToken,
    };
  }
}
