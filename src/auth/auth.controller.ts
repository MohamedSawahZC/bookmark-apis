import { Controller, HttpCode, Post } from '@nestjs/common/decorators';
import { AuthService } from './auth.service';
import { Body, HttpStatus } from '@nestjs/common';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto : AuthDto) {
    return this.authService.signup(dto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signin(@Body() dto : AuthDto) {
    return this.authService.login(dto);
  }
}
