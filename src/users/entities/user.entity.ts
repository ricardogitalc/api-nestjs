export enum Role {
  USER = 'USER',
  ADMIN = 'ADMIN',
}

export enum Provider {
  CREDENTIALS = 'CREDENTIALS',
  GOOGLE = 'GOOGLE',
}

export class User {
  role: Role;
  provider: Provider;
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  profileUrl?: string;
  phone?: string;
  cpf?: String;
  zipCode?: String;
  city?: String;
  state?: String;
  address?: String;
  district?: String;
  number?: String;
  verified: boolean;
  createdAt: Date;
  updatedAt: Date;
}
