import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  UseGuards,
  Res,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Public } from 'src/common/decorators/public.decorator';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import {
  loginUserInput,
  registerUserInput,
  refreshTokenInput,
  resetPwdSentInput,
  resetPwdConfInput,
} from './dto/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
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
  @Post('verify-register')
  async verifyRegister(@Body('verificationToken') verificationToken: string) {
    return this.authService.verifyRegister(verificationToken);
  }

  @Public()
  @Post('refresh')
  async refresh(@Body() refreshTokenInput: refreshTokenInput) {
    const { accessToken, refreshToken } = await this.authService.refreshToken(
      refreshTokenInput.refreshToken,
    );
    return { accessToken, refreshToken };
  }

  @Public()
  @Post('reset-pwd')
  async resetPwdSent(@Body() resetPwdSentInput: resetPwdSentInput) {
    return this.authService.resetPwdSent(resetPwdSentInput.email);
  }

  @Public()
  @Post('reset-pwd/confirm')
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
  async googleAuthRedirect(@Req() req, @Res() res) {
    try {
      const { accessToken, refreshToken } = await this.authService.googleLogin(
        req.user,
      );

      const redirectUrl = `${this.configService.get('FRONTEND_URL')}/callback?accessToken=${accessToken}&refreshToken=${refreshToken}`;
      return res.redirect(redirectUrl);
    } catch (error) {
      return res.redirect(`${this.configService.get('FRONTEND_URL')}/entrar`);
    }
  }
}
