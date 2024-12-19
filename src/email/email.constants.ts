export const EMAIL_TEMPLATES = {
  RESET_PASSWORD: (firstName: string, resetLink: string) => `
    <h1>Redefinição de Senha</h1>
    <p>Olá ${firstName},</p>
    <p>Você solicitou a redefinição de sua senha. Clique no link abaixo para continuar:</p>
    <a href="${resetLink}">Redefinir Senha</a>
    <p>Se você não solicitou esta redefinição, ignore este email.</p>
    <p>O link expira em 1 hora.</p>
  `,
  REGISTER_VERIFICATION: (firstName: string, verificationLink: string) => `
    <h1>Bem-vindo! Confirme seu email</h1>
    <p>Olá ${firstName},</p>
    <p>Obrigado por se registrar! Para ativar sua conta, clique no link abaixo:</p>
    <a href="${verificationLink}">Verificar Conta</a>
    <p>Se você não criou esta conta, ignore este email.</p>
    <p>O link expira em 1 hora.</p>
  `,
};
