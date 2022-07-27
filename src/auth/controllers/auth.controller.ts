import {
  Body,
  Req,
  Controller,
  HttpCode,
  Post,
  UseGuards,
  Res,
  Get,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from '../services/auth.service';
import { LocalAuthGuard } from '../guards/localAuth.guard';
import RequestWithUser from '../interfaces/requestWithUser.interface';
import RegisterDto from '../dto/register.dto';
import JwtAuthGuard from '../guards/jwt-auth.guard';
import { ApiTags } from '@nestjs/swagger';
import JwtRefreshGuard from '../guards/jwt-refresh.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registrationData: RegisterDto) {
    return this.authService.register(registrationData);
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  async refresh(@Req() request: RequestWithUser, @Res() response: Response) {
    const accessTokenCookie = this.authService.getCookieWithJwtToken(
      request.user.id,
    );
    const { cookie: refreshTokenCookie, token: refreshToken } =
      this.authService.getCookieWithJwtRefreshToken(request.user.id);

    await this.authService.setCurrentRefreshToken(
      refreshToken,
      request.user.id,
    );

    response.setHeader('Set-Cookie', [accessTokenCookie, refreshTokenCookie]);

    request.user.password = undefined;
    return response.json(request.user);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('login')
  async logIn(@Req() request: RequestWithUser, @Res() response: Response) {
    const { user } = request;

    const accessTokenCookie = this.authService.getCookieWithJwtToken(user.id);
    const { cookie: refreshTokenCookie, token: refreshToken } =
      this.authService.getCookieWithJwtRefreshToken(user.id);

    await this.authService.setCurrentRefreshToken(refreshToken, user.id);

    response.setHeader('Set-Cookie', [accessTokenCookie, refreshTokenCookie]);

    user.password = undefined;
    return response.sendStatus(201);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
    await this.authService.removeRefreshToken(request.user.id);
    response.setHeader('Set-Cookie', this.authService.getCookieForLogOut());
    return response.sendStatus(200);
  }

  @UseGuards(JwtAuthGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = undefined;
    return user;
  }
}
