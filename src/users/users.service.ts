import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { CONFIG_MESSAGES } from 'src/config/config';
import {
  CreateUserInput,
  UpdateUserInput,
  UpdateProfileInput,
} from './inputs/user.inputs';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async createUser(createUserInput: CreateUserInput) {
    const hashedPassword = await bcrypt.hash(createUserInput.password, 10);
    return this.prisma.user.create({
      data: {
        firstName: createUserInput.firstName,
        lastName: createUserInput.lastName,
        email: createUserInput.email,
        password: hashedPassword,
        phone: createUserInput.phone,
      },
    });
  }

  getAllUsers() {
    return this.prisma.user.findMany();
  }

  async getUserById(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException(CONFIG_MESSAGES.userNotFound);
    }

    return user;
  }

  async updateUserById(
    id: number,
    updateUserInput: Partial<Omit<UpdateUserInput, 'id'>>,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: Number(id) },
    });

    if (!user) {
      throw new NotFoundException(CONFIG_MESSAGES.userNotFound);
    }

    return this.prisma.user.update({
      where: { id: Number(id) },
      data: updateUserInput,
    });
  }

  async deleteUserById(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });

    if (!user) {
      throw new NotFoundException(CONFIG_MESSAGES.userNotFound);
    }

    return this.prisma.user.delete({
      where: { id },
    });
  }

  async updateUserProfile(
    userId: number,
    updateProfileInput: UpdateProfileInput,
  ) {
    if (updateProfileInput.currentPassword && updateProfileInput.newPassword) {
      const currentUser = await this.getUserById(userId);
      const isPasswordValid = await bcrypt.compare(
        updateProfileInput.currentPassword,
        currentUser.password,
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('A senha atual está incorreta');
      }

      const hashedNewPassword = await bcrypt.hash(
        updateProfileInput.newPassword,
        10,
      );

      const { currentPassword, newPassword, ...restInput } = updateProfileInput;
      return this.updateUserById(userId, {
        ...restInput,
        password: hashedNewPassword,
      });
    }

    const { currentPassword, newPassword, ...updateData } = updateProfileInput;
    return this.updateUserById(userId, updateData);
  }
}
