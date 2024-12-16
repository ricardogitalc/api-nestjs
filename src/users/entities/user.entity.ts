export class User {
  id: number;
  role: string;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  whatsapp?: string;
  verified: boolean;
  createdAt: Date;
  updatedAt: Date;
}
