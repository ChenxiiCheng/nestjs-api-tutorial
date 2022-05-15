import { Controller, Post, Body } from '@nestjs/common';
import { AuthDTO } from './dto';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() body: AuthDTO) {
    return this.authService.signup(body);
  }

  @Post('signin')
  signin(@Body() body: AuthDTO) {
    return this.authService.signin(body);
  }
}
