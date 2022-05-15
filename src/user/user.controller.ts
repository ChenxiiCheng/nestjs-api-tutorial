import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { User } from '@prisma/client';
import { Request as ExpressRequest } from 'express';
import { JwtGuard } from 'src/auth/auth.guard';
import { GetUser } from 'src/auth/decorator';

@Controller('user')
export class UserController {
  // @UseGuards(AuthGuard('jwt'))
  // @Request() req: ExpressRequest
  @UseGuards(JwtGuard)
  @Get('me')
  async getMe(@GetUser('') user: User) {
    return user;
  }
}
