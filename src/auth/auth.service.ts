import {
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import type { StringValue } from 'ms';
import type { Role } from '../generated/prisma/enums';
import { PrismaService } from '../database/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RedisService } from '../redis/redis.service';
import {
  sanitizeUserInput,
  stripPrivilegedFields,
} from '../common/security/safe-user-input.util';

type RefreshPayload = {
  sub: number;
  email: string;
  role: Role;
  sid: string;
  jti: string;
};

type RefreshSession = {
  hash: string;
  userId: number;
  sessionId: string;
  jti: string;
  createdAt: string;
  lastActivity: string;
  userAgent?: string;
  device?: string;
};

type SecurityEventType =
  | 'login_success'
  | 'login_failed'
  | 'login_blocked'
  | 'refresh_success'
  | 'refresh_invalid'
  | 'refresh_reuse'
  | 'csrf_invalid'
  | 'session_revoked'
  | 'suspicious_activity';

type SecurityEventSeverity = 'low' | 'medium' | 'high';

type SecurityEvent = {
  id: string;
  userId?: number;
  email?: string;
  sessionId?: string;
  type: SecurityEventType;
  severity: SecurityEventSeverity;
  message: string;
  timestamp: string;
  userAgent?: string;
  ip?: string;
  details?: Record<string, unknown>;
};

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {}

  async register(dto: RegisterDto) {
    const safeDto = sanitizeUserInput(dto as unknown as Record<string, unknown>, [
      'email',
      'password',
    ]);
    const email = String(safeDto.email ?? '').trim().toLowerCase();
    const password = String(safeDto.password ?? '');

    const existingUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await this.prisma.user.create({
      data: stripPrivilegedFields({
        email,
        password: passwordHash,
      }) as {
        email: string;
        password: string;
      },
    });

    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
    };
  }

  private getRefreshSessionKey(sessionId: string) {
    return `session:refresh:${sessionId}`;
  }

  private getUsedRefreshKey(userId: number) {
    return `used:refresh:${userId}`;
  }

  private getLoginAttemptKey(email: string) {
    return `login:attempts:${email.toLowerCase()}`;
  }

  private getLoginBlockKey(email: string) {
    return `login:block:${email.toLowerCase()}`;
  }

  private getDeviceLabel(userAgent?: string) {
    if (!userAgent) {
      return 'Unknown device';
    }

    const ua = userAgent.toLowerCase();

    if (ua.includes('mobile')) {
      return ua.includes('android') ? 'Android mobile' : 'Mobile device';
    }

    if (ua.includes('ipad') || ua.includes('iphone') || ua.includes('ios')) {
      return 'iPhone/iPad';
    }

    if (ua.includes('windows')) {
      return 'Windows desktop';
    }

    if (ua.includes('mac')) {
      return 'Mac desktop';
    }

    if (ua.includes('linux')) {
      return 'Linux desktop';
    }

    return 'Browser session';
  }

  private getSecurityEventsKey(userId: number) {
    return `security:events:${userId}`;
  }

  private assertResourceOwnership(
    currentUserId: number,
    resourceOwnerId: number,
    resourceName: string,
  ) {
    if (currentUserId !== resourceOwnerId) {
      throw new ForbiddenException(
        `You do not have access to this ${resourceName}.`,
      );
    }
  }

  private async recordSecurityEvent(options: {
    userId?: number;
    email?: string;
    sessionId?: string;
    type: SecurityEventType;
    severity?: SecurityEventSeverity;
    message: string;
    userAgent?: string;
    ip?: string;
    details?: Record<string, unknown>;
  }) {
    const redis = this.redisService.getClient();
    const event: SecurityEvent = {
      id: randomUUID(),
      userId: options.userId,
      email: options.email,
      sessionId: options.sessionId,
      type: options.type,
      severity: options.severity ?? 'low',
      message: options.message,
      timestamp: new Date().toISOString(),
      userAgent: options.userAgent,
      ip: options.ip,
      details: options.details,
    };

    const key = options.userId
      ? this.getSecurityEventsKey(options.userId)
      : 'security:events:anonymous';

    await redis.zadd(key, Date.now(), JSON.stringify(event));
    await redis.zremrangebyrank(key, 0, -101);
  }

  async recordCsrfFailure(
    userId?: number,
    userAgent?: string,
    details?: Record<string, unknown>,
  ) {
    await this.recordSecurityEvent({
      userId,
      type: 'csrf_invalid',
      severity: 'high',
      message: 'Rejected a request with an invalid CSRF token',
      userAgent,
      details,
    });
  }

  async getSecurityEvents(userId: number, limit = 50) {
    this.assertResourceOwnership(userId, userId, 'security events');

    const rawEvents = await this.redisService
      .getClient()
      .zrevrangebyscore(this.getSecurityEventsKey(userId), Date.now(), 0, 'LIMIT', 0, limit);

    return rawEvents
      .map((item) => {
        try {
          return JSON.parse(item) as SecurityEvent;
        } catch {
          return null;
        }
      })
      .filter((event): event is SecurityEvent => !!event);
  }

  async analyzeSuspiciousActivity(userId: number) {
    this.assertResourceOwnership(userId, userId, 'security analysis');

    const events = await this.getSecurityEvents(userId, 100);
    const now = Date.now();
    const windowMs = 1000 * 60 * 60 * 24;
    const recentEvents = events.filter(
      (event) => now - new Date(event.timestamp).getTime() <= windowMs,
    );

    const reasons: string[] = [];
    let score = 0;

    const failedLogins = recentEvents.filter(
      (event) => event.type === 'login_failed',
    ).length;
    const invalidRefreshes = recentEvents.filter(
      (event) => event.type === 'refresh_invalid' || event.type === 'refresh_reuse',
    ).length;
    const csrfInvalid = recentEvents.filter(
      (event) => event.type === 'csrf_invalid',
    ).length;

    if (failedLogins >= 3) {
      score += 35;
      reasons.push('Multiple failed login attempts in the last 24 hours');
    }

    if (invalidRefreshes >= 1) {
      score += 45;
      reasons.push('Detected invalid or replayed refresh token activity');
    }

    if (csrfInvalid >= 1) {
      score += 25;
      reasons.push('Detected invalid CSRF attempts');
    }

    const uniqueAgents = new Set(
      recentEvents
        .map((event) => event.userAgent)
        .filter((value): value is string => !!value),
    );

    if (uniqueAgents.size > 2) {
      score += 20;
      reasons.push('Activity originated from multiple user-agent profiles');
    }

    const isSuspicious = score >= 50 || reasons.length >= 2;

    return {
      userId,
      isSuspicious,
      score,
      reasons: reasons.length > 0 ? reasons : ['No suspicious activity detected'],
      events: recentEvents.slice(0, 10),
      windowHours: 24,
      generatedAt: new Date().toISOString(),
    };
  }

  private async checkLoginRateLimit(email: string) {
    const key = this.getLoginAttemptKey(email);
    const blockKey = this.getLoginBlockKey(email);
    const blockedUntil = await this.redisService.getClient().get(blockKey);

    if (blockedUntil) {
      const remainingMs = Number(blockedUntil) - Date.now();
      if (remainingMs > 0) {
        throw new UnauthorizedException(
          `Too many login attempts. Try again in ${Math.ceil(remainingMs / 1000)}s`,
        );
      }

      await this.redisService.getClient().del(blockKey);
    }

    const attempts = await this.redisService.getClient().incr(key);
    if (attempts === 1) {
      await this.redisService.getClient().expire(key, 60 * 15);
    }

    if (attempts > 5) {
      const blockMs = 60 * 1000;
      await this.redisService
        .getClient()
        .set(blockKey, String(Date.now() + blockMs));
      await this.redisService.getClient().expire(blockKey, 60);
      await this.recordSecurityEvent({
        email,
        type: 'login_blocked',
        severity: 'high',
        message: 'User exceeded the login attempts threshold and was temporarily blocked',
        details: {
          attempts,
          blockMs,
        },
      });
      throw new UnauthorizedException(
        'Too many login attempts. Please wait 60 seconds.',
      );
    }
  }

  private async resetLoginRateLimit(email: string) {
    await this.redisService.getClient().del(this.getLoginAttemptKey(email));
    await this.redisService.getClient().del(this.getLoginBlockKey(email));
  }

  private generateTokens(
    userId: number,
    email: string,
    role: Role,
    sessionId: string,
  ) {
    const payload = {
      sub: userId,
      email,
      role,
      sid: sessionId,
    };

    const accessSecret =
      this.configService.getOrThrow<string>('JWT_ACCESS_SECRET');
    const refreshSecret =
      this.configService.getOrThrow<string>('JWT_REFRESH_SECRET');
    const accessTokenExpiresIn =
      this.configService.getOrThrow<StringValue>('JWT_ACCESS_EXPIRES');
    const refreshTokenExpiresIn = this.configService.getOrThrow<StringValue>(
      'JWT_REFRESH_EXPIRES',
    );

    const accessToken = this.jwtService.sign(payload, {
      secret: accessSecret,
      expiresIn: accessTokenExpiresIn,
    });

    const refreshToken = this.jwtService.sign(
      {
        ...payload,
        jti: randomUUID(),
      },
      {
        secret: refreshSecret,
        expiresIn: refreshTokenExpiresIn,
      },
    );

    return {
      accessToken,
      refreshToken,
    };
  }

  private verifyRefreshToken(refreshToken: string): RefreshPayload {
    try {
      const payload = this.jwtService.verify<RefreshPayload>(refreshToken, {
        secret: this.configService.getOrThrow<string>('JWT_REFRESH_SECRET'),
      });

      if (!payload.sid || !payload.jti) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      return payload;
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async login(dto: LoginDto, userAgent?: string) {
    const email = dto.email.trim().toLowerCase();
    await this.checkLoginRateLimit(email);

    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      await this.checkLoginRateLimit(email);
      await this.recordSecurityEvent({
        email,
        type: 'login_failed',
        severity: 'medium',
        message: 'Login attempt failed: user not found',
        details: {
          reason: 'user_not_found',
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const passwordMatch = await bcrypt.compare(dto.password, user.password);

    if (!passwordMatch) {
      await this.checkLoginRateLimit(email);
      await this.recordSecurityEvent({
        userId: user.id,
        email,
        type: 'login_failed',
        severity: 'medium',
        message: 'Login attempt failed: invalid password',
        userAgent,
        details: {
          reason: 'invalid_password',
        },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.role) {
      throw new UnauthorizedException('User role is not set');
    }

    await this.resetLoginRateLimit(email);
    await this.recordSecurityEvent({
     userId: user.id,
     email,
     type: 'login_success',
     severity: 'low',
     message: 'User logged in successfully',
     userAgent,
     sessionId: 'login',
     details: {
       device: this.getDeviceLabel(userAgent),
     },
    });

    const sessionId = randomUUID();
    const now = new Date().toISOString();
    const tokens = this.generateTokens(
      user.id,
      user.email,
      user.role,
      sessionId,
    );

    const refreshPayload = this.verifyRefreshToken(tokens.refreshToken);
    const refreshHash = await bcrypt.hash(tokens.refreshToken, 10);

    await this.redisService.getClient().set(
      this.getRefreshSessionKey(sessionId),
      JSON.stringify({
        hash: refreshHash,
        userId: user.id,
        sessionId,
        jti: refreshPayload.jti,
        createdAt: now,
        lastActivity: now,
        userAgent,
        device: this.getDeviceLabel(userAgent),
      } satisfies RefreshSession),
      'EX',
      60 * 60 * 24 * 30,
    );

    return tokens;
  }

  async refresh(refreshToken?: string, userAgent?: string) {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }

    const payload = this.verifyRefreshToken(refreshToken);
    const redis = this.redisService.getClient();
    const sessionKey = this.getRefreshSessionKey(payload.sid);
    const usedKey = this.getUsedRefreshKey(payload.sub);

    const oldSession = await redis.get(sessionKey);

    if (!oldSession) {
      await this.recordSecurityEvent({
        userId: payload.sub,
        type: 'refresh_invalid',
        severity: 'high',
        message: 'Refresh token was rejected because the session is missing',
        userAgent,
        details: {
          sessionId: payload.sid,
          jti: payload.jti,
        },
      });
      throw new UnauthorizedException('Session expired');
    }

    let storedSession: RefreshSession;

    try {
      storedSession = JSON.parse(oldSession);
    } catch {
      throw new UnauthorizedException('Invalid session');
    }

    this.assertResourceOwnership(payload.sub, storedSession.userId, 'session');

    if (storedSession.sessionId !== payload.sid) {
      throw new UnauthorizedException('Invalid session');
    }

    if (storedSession.jti !== payload.jti) {
      throw new UnauthorizedException('Refresh token already used');
    }

    const isJtiUsed = await redis.sismember(usedKey, payload.jti);

    if (isJtiUsed) {
      await this.recordSecurityEvent({
        userId: payload.sub,
        sessionId: payload.sid,
        type: 'refresh_reuse',
        severity: 'high',
        message: 'Detected refresh token replay/reuse',
        userAgent,
        details: {
          jti: payload.jti,
        },
      });
      throw new UnauthorizedException('Refresh token already used');
    }

    const isValid = await bcrypt.compare(refreshToken, storedSession.hash);

    if (!isValid) {
      await this.recordSecurityEvent({
        userId: payload.sub,
        sessionId: payload.sid,
        type: 'refresh_invalid',
        severity: 'high',
        message: 'Refresh token hash validation failed',
        userAgent,
        details: {
          jti: payload.jti,
        },
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.role) {
      throw new UnauthorizedException('User role is not set');
    }

    const tokens = this.generateTokens(
      user.id,
      user.email,
      user.role,
      payload.sid,
    );

    const newRefreshPayload = this.verifyRefreshToken(tokens.refreshToken);
    const newHash = await bcrypt.hash(tokens.refreshToken, 10);
    const now = new Date().toISOString();

    const newSession = JSON.stringify({
      hash: newHash,
      userId: user.id,
      sessionId: payload.sid,
      jti: newRefreshPayload.jti,
      createdAt: storedSession.createdAt ?? now,
      lastActivity: now,
      userAgent: userAgent ?? storedSession.userAgent,
      device: this.getDeviceLabel(userAgent ?? storedSession.userAgent),
    } satisfies RefreshSession);

    const script = `
      local current = redis.call('GET', KEYS[1])
      local alreadyUsed = redis.call('SISMEMBER', KEYS[2], ARGV[4])

      if alreadyUsed == 1 then
        return 0
      end

      if current ~= ARGV[1] then
        return 0
      end

      redis.call('SADD', KEYS[2], ARGV[4])
      redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])

      return 1
    `;

    const result = await redis.eval(
      script,
      2,
      sessionKey,
      usedKey,
      oldSession,
      newSession,
      60 * 60 * 24 * 30,
      payload.jti,
    );

    if (result !== 1) {
      await this.recordSecurityEvent({
        userId: payload.sub,
        sessionId: payload.sid,
        type: 'refresh_reuse',
        severity: 'high',
        message: 'Refresh token was rejected as already used during a rotation race',
        userAgent,
        details: {
          jti: payload.jti,
        },
      });
      throw new UnauthorizedException('Refresh token already used');
    }

    await this.recordSecurityEvent({
      userId: payload.sub,
      sessionId: payload.sid,
      type: 'refresh_success',
      severity: 'low',
      message: 'Refresh token rotated successfully',
      userAgent,
      details: {
        jti: newRefreshPayload.jti,
      },
    });

    return tokens;
  }

  async logout(refreshToken?: string) {
    if (!refreshToken) {
      return { message: 'Logged out successfully' };
    }

    try {
      const payload = this.verifyRefreshToken(refreshToken);

      await this.redisService
        .getClient()
        .del(this.getRefreshSessionKey(payload.sid));

      await this.redisService
        .getClient()
        .srem(this.getUsedRefreshKey(payload.sub), payload.jti);

      await this.recordSecurityEvent({
        userId: payload.sub,
        sessionId: payload.sid,
        type: 'session_revoked',
        severity: 'low',
        message: 'User logged out and session was revoked',
        details: {
          jti: payload.jti,
        },
      });

      return { message: 'Logged out successfully' };
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async getActiveSessions(userId: number, currentSessionId?: string) {
    const redis = this.redisService.getClient();
    const keys = await redis.keys('session:refresh:*');
    const sessions: Array<{
      sessionId: string;
      userId: number;
      createdAt: string;
      lastActivity: string;
      device: string;
      userAgent?: string;
      isCurrent: boolean;
    }> = [];

    for (const key of keys) {
      const raw = await redis.get(key);
      if (!raw) {
        continue;
      }

      let session: RefreshSession;
      try {
        session = JSON.parse(raw) as RefreshSession;
      } catch {
        continue;
      }

      if (session.userId !== userId) {
        continue;
      }

      this.assertResourceOwnership(userId, session.userId, 'session');

      sessions.push({
        sessionId: session.sessionId,
        userId: session.userId,
        createdAt: session.createdAt ?? new Date().toISOString(),
        lastActivity: session.lastActivity ?? session.createdAt ?? new Date().toISOString(),
        device: session.device ?? this.getDeviceLabel(session.userAgent),
        userAgent: session.userAgent,
        isCurrent: session.sessionId === currentSessionId,
      });
    }

    return sessions.sort(
      (a, b) =>
        new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime(),
    );
  }

  async revokeSession(userId: number, sessionId: string, currentSessionId?: string) {
    if (sessionId === currentSessionId) {
      throw new UnauthorizedException('Cannot revoke the current session');
    }

    const redis = this.redisService.getClient();
    const key = this.getRefreshSessionKey(sessionId);
    const raw = await redis.get(key);

    if (!raw) {
      throw new UnauthorizedException('Session not found');
    }

    const session = JSON.parse(raw) as RefreshSession;

    this.assertResourceOwnership(userId, session.userId, 'session');

    await redis.del(key);
    await redis.srem(this.getUsedRefreshKey(userId), session.jti);
    await this.recordSecurityEvent({
      userId,
      sessionId,
      type: 'session_revoked',
      severity: 'medium',
      message: 'User manually revoked a session from the device list',
      userAgent: session.userAgent,
      details: {
        revokedSessionId: sessionId,
      },
    });

    return {
      sessionId,
      revoked: true,
    };
  }

  async revokeAllOtherSessions(userId: number, currentSessionId: string) {
    this.assertResourceOwnership(userId, userId, 'session list');

    const sessions = await this.getActiveSessions(userId, currentSessionId);
    let revoked = 0;

    for (const session of sessions) {
      if (session.sessionId === currentSessionId) {
        continue;
      }

      await this.redisService.getClient().del(this.getRefreshSessionKey(session.sessionId));
      revoked += 1;
      await this.recordSecurityEvent({
        userId,
        sessionId: session.sessionId,
        type: 'session_revoked',
        severity: 'medium',
        message: 'User revoked all other sessions',
        details: {
          currentSessionId,
        },
      });
    }

    return {
      revoked,
      currentSessionId,
    };
  }

  async revokeSuspiciousSessions(userId: number, sessionIds: string[]) {
    this.assertResourceOwnership(userId, userId, 'session list');

    if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
      return { revoked: 0 };
    }

    let revoked = 0;

    for (const sessionId of sessionIds) {
      try {
        await this.revokeSession(userId, sessionId);
        revoked += 1;
      } catch {
        // ignore invalid or already revoked sessions
      }
    }

    if (revoked > 0) {
      await this.recordSecurityEvent({
        userId,
        type: 'suspicious_activity',
        severity: 'high',
        message: 'Suspicious sessions were revoked by the user',
        details: {
          revokedSessionIds: sessionIds,
        },
      });
    }

    return { revoked };
  }
}
