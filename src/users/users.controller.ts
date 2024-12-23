import {
  Controller,
  Get,
  Delete,
  Body,
  Param,
  ParseIntPipe,
  ValidationPipe,
  Patch,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateUserInput, UpdateProfileInput } from './inputs/user.inputs';
import { Role } from '@prisma/client';
import { Roles } from 'src/common/decorators/roles.decorator';
import { CurrentUser } from 'src/common/decorators/current-user.decorator';
import * as bcrypt from 'bcrypt';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get('profile')
  async getProfile(@CurrentUser() user: { sub: number }) {
    return this.usersService.getUserById(user.sub);
  }

  @Patch('profile')
  async updateProfile(
    @CurrentUser() user: { sub: number },
    @Body(new ValidationPipe()) updateProfileInput: UpdateProfileInput,
  ) {
    return this.usersService.updateUserProfile(user.sub, updateProfileInput);
  }

  @Delete('profile')
  async deleteProfile(@CurrentUser() user: { sub: number }) {
    return this.usersService.deleteUserById(user.sub);
  }

  @Get()
  @Roles(Role.ADMIN)
  getAllUsers() {
    return this.usersService.getAllUsers();
  }

  @Get(':id')
  @Roles(Role.ADMIN)
  getUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.getUserById(id);
  }

  @Patch(':id')
  @Roles(Role.ADMIN)
  async updateUserById(
    @Param('id', ParseIntPipe) id: number,
    @Body(new ValidationPipe())
    updateUserInput: Partial<Omit<UpdateUserInput, 'id'>>,
  ) {
    if (updateUserInput.password) {
      const hashedPassword = await bcrypt.hash(updateUserInput.password, 10);
      updateUserInput.password = hashedPassword;
    }
    return this.usersService.updateUserById(id, updateUserInput);
  }

  @Delete(':id')
  @Roles(Role.ADMIN)
  deleteUserById(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.deleteUserById(id);
  }
}
