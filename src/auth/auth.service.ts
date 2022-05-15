import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as Argon from 'argon2';
import { User } from '@prisma/client';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO } from './dto';
import { ReturnUserWithJwt } from './auth.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async signup(dto: AuthDTO) {
    const hash = await Argon.hash(dto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });
      delete user.hash;
      return this.generateToken(user);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        // https://www.prisma.io/docs/reference/api-reference/error-reference#error-codes
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signin(dto: AuthDTO) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Crendentials incorrect');
    }
    const isPasswordMatch = await Argon.verify(user.hash, dto.password);
    if (!isPasswordMatch) {
      throw new ForbiddenException('Crendentials incorrect');
    }
    delete user.hash;
    return this.generateToken(user);
  }

  private async generateToken(user: User): Promise<ReturnUserWithJwt> {
    const payload = {
      sub: user.id,
      email: user.email,
    };
    const jwt = await this.jwtService.signAsync(payload, {
      expiresIn: '7d',
      secret: this.configService.get('JWT_SECRET'),
    });
    return { ...user, accessToken: jwt };
  }
}
