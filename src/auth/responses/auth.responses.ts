export class LoginResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
}

export class RegisterResponse {
  message: string;
  verificationToken: string;
}

export class RefreshResponse {
  message: string;
  accessToken: string;
  refreshToken: string;
}

export class ResetResponse {
  message: string;
  resetToken: string;
}
