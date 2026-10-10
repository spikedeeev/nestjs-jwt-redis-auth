import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';

const isProduction = process.env.NODE_ENV === 'production';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private readonly cookieOptions = {
    httpOnly: true,
    path: '/',
    secure: isProduction,
    sameSite: 'lax' as const,
    maxAge: 1000 * 60 * 60 * 24 * 30,
  };

  private readonly csrfCookieOptions = {
    httpOnly: false,
    path: '/',
    secure: isProduction,
    sameSite: 'lax' as const,
    maxAge: 1000 * 60 * 60 * 24 * 30,
  };

  private extractCookie(req: Request, cookieName: string): string | undefined {
    const cookieHeader = req.headers.cookie;

    if (!cookieHeader) {
      return undefined;
    }

    const cookies = cookieHeader
      .split(';')
      .map((part) => part.trim())
      .filter((part) => part.length > 0);

    const cookie = cookies.find((part) => part.startsWith(`${cookieName}=`));

    if (!cookie) {
      return undefined;
    }

    return decodeURIComponent(cookie.slice(cookieName.length + 1));
  }

  private extractRefreshToken(req: Request): string | undefined {
    return this.extractCookie(req, 'refresh_token');
  }

  private getCsrfTokenFromHeader(req: Request): string | undefined {
    const headerValue = req.headers['x-csrf-token'];

    if (Array.isArray(headerValue)) {
      return headerValue[0];
    }

    return headerValue;
  }

  private validateCsrf(req: Request) {
    const cookieToken = this.extractCookie(req, 'csrf_token');
    const headerToken = this.getCsrfTokenFromHeader(req);

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      void this.authService.recordCsrfFailure(
        undefined,
        Array.isArray(req.headers['user-agent'])
          ? req.headers['user-agent'][0]
          : req.headers['user-agent'],
        {
          cookieTokenPresent: !!cookieToken,
          headerTokenPresent: !!headerToken,
          cookieName: 'csrf_token',
        },
      );
      throw new UnauthorizedException('Invalid CSRF token');
    }
  }

  private setSessionCookies(res: Response, refreshToken: string, csrfToken: string) {
    res.cookie('refresh_token', refreshToken, this.cookieOptions);
    res.cookie('csrf_token', csrfToken, this.csrfCookieOptions);
  }

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.login(dto, req.headers['user-agent']);
    const csrfToken = randomBytes(32).toString('hex');

    this.setSessionCookies(res, tokens.refreshToken, csrfToken);

    return {
      accessToken: tokens.accessToken,
      csrfToken,
    };
  }

  @Post('refresh')
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    this.validateCsrf(req);

    const refreshToken = this.extractRefreshToken(req);
    const tokens = await this.authService.refresh(
      refreshToken,
      req.headers['user-agent'],
    );
    const csrfToken = randomBytes(32).toString('hex');

    this.setSessionCookies(res, tokens.refreshToken, csrfToken);

    return {
      accessToken: tokens.accessToken,
      csrfToken,
    };
  }

  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    this.validateCsrf(req);

    const refreshToken = this.extractRefreshToken(req);

    await this.authService.logout(refreshToken);

    res.clearCookie('refresh_token', {
      httpOnly: true,
      path: '/',
      secure: isProduction,
      sameSite: 'lax',
    });
    res.clearCookie('csrf_token', {
      httpOnly: false,
      path: '/',
      secure: isProduction,
      sameSite: 'lax',
    });

    return {
      message: 'Logged out successfully',
    };
  }

  @Get('sessions')
  @UseGuards(JwtAuthGuard)
  async getSessions(@Req() req: any) {
    return this.authService.getActiveSessions(req.user.id, req.user.sid);
  }

  @Delete('sessions/:sessionId')
  @UseGuards(JwtAuthGuard)
  async revokeSession(@Req() req: any, @Param('sessionId') sessionId: string) {
    return this.authService.revokeSession(req.user.id, sessionId, req.user.sid);
  }

  @Post('sessions/logout/all-other')
  @UseGuards(JwtAuthGuard)
  async revokeAllOtherSessions(@Req() req: any) {
    return this.authService.revokeAllOtherSessions(req.user.id, req.user.sid);
  }

  @Post('sessions/revoke-suspicious')
  @UseGuards(JwtAuthGuard)
  async revokeSuspiciousSessions(
    @Req() req: any,
    @Body() body: { sessionIds: string[] },
  ) {
    return this.authService.revokeSuspiciousSessions(req.user.id, body.sessionIds);
  }

  @Get('security-events')
  @UseGuards(JwtAuthGuard)
  async getSecurityEvents(@Req() req: any) {
    return this.authService.getSecurityEvents(req.user.id, 50);
  }

  @Get('security-analysis')
  @UseGuards(JwtAuthGuard)
  async getSecurityAnalysis(@Req() req: any) {
    return this.authService.analyzeSuspiciousActivity(req.user.id);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  profile(@Req() req: any) {
    return {
      message: 'Protected route',
      user: req.user,
    };
  }

  @Get('admin')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  adminOnly() {
    return {
      message: 'Welcome, admin!',
    };
  }
}
