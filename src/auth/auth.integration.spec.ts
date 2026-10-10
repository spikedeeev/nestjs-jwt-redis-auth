import { jest } from '@jest/globals';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { Test, TestingModule } from '@nestjs/testing';
import request from 'supertest';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { PrismaService } from '../database/prisma.service';
import { RedisService } from '../redis/redis.service';

const redisState = new Map<string, string>();
const redisSets = new Map<string, Set<string>>();

function parseSetCookieHeader(
  headers: string[] | undefined,
  cookieName: string,
) {
  const cookie = headers
    ?.find((entry) => entry.startsWith(`${cookieName}=`))
    ?.split(';')[0];

  return cookie ? cookie.split('=')[1] : undefined;
}

describe('Auth API integration', () => {
  let app: INestApplication;

  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    process.env.JWT_ACCESS_SECRET = 'test-access-secret';
    process.env.JWT_REFRESH_SECRET = 'test-refresh-secret';
    process.env.JWT_ACCESS_EXPIRES = '15m';
    process.env.JWT_REFRESH_EXPIRES = '30d';
  });

  beforeEach(async () => {
    redisState.clear();
    redisSets.clear();

    const users = new Map<string, any>();
    let userIdCounter = 1;

    const prismaMock = {
      user: {
        create: jest.fn(async ({ data }) => {
          const saved = {
            id: userIdCounter++,
            email: data.email,
            password: data.password,
            role: 'USER',
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          users.set(saved.email, saved);
          return saved;
        }),
        findUnique: jest.fn(async ({ where }) => {
          if (where.id !== undefined) {
            return [...users.values()].find((user) => user.id === where.id) ?? null;
          }

          const email = String(where.email ?? '').toLowerCase();
          return users.get(email) ?? null;
        }),
      },
    };

    const redisClient = {
      get: jest.fn(async (key: string) => redisState.get(key) ?? null),
      set: jest.fn(async (key: string, value: string) => {
        redisState.set(key, value);
        return 'OK';
      }),
      del: jest.fn(async (key: string) => {
        redisState.delete(key);
        return 1;
      }),
      incr: jest.fn(async (key: string) => {
        const current = Number(redisState.get(key) ?? '0');
        const next = current + 1;
        redisState.set(key, String(next));
        return next;
      }),
      expire: jest.fn(async () => true),
      sismember: jest.fn(async (key: string, member: string) => {
        return redisSets.get(key)?.has(member) ?? false;
      }),
      sadd: jest.fn(async (key: string, ...members: string[]) => {
        const set = redisSets.get(key) ?? new Set<string>();
        for (const member of members) {
          set.add(member);
        }
        redisSets.set(key, set);
        return set.size;
      }),
      srem: jest.fn(async (key: string, member: string) => {
        const set = redisSets.get(key);
        if (!set) {
          return 0;
        }

        const removed = set.delete(member);
        if (!set.size) {
          redisSets.delete(key);
        }

        return removed ? 1 : 0;
      }),
      keys: jest.fn(async (pattern: string) => {
        const keys: string[] = [];

        for (const key of redisState.keys()) {
          if (
            pattern === 'session:refresh:*' &&
            key.startsWith('session:refresh:')
          ) {
            keys.push(key);
          }
        }

        return keys;
      }),
      eval: jest.fn(
        async (_script: string, _numkeys: number, ...args: string[]) => {
          const [sessionKey, usedKey, oldSession, newSession, _ttl, jti] = args;

          if (redisState.get(sessionKey) !== oldSession) {
            return 0;
          }

          const set = redisSets.get(usedKey) ?? new Set<string>();
          if (set.has(jti)) {
            return 0;
          }

          set.add(jti);
          redisSets.set(usedKey, set);
          redisState.set(sessionKey, newSession);
          return 1;
        },
      ),
      zadd: jest.fn(async () => 1),
      zremrangebyrank: jest.fn(async () => 1),
      zrevrangebyscore: jest.fn(async () => []),
    };

    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true }),
        PassportModule.register({ defaultStrategy: 'jwt' }),
        JwtModule.registerAsync({
          inject: [ConfigService],
          useFactory: (configService: ConfigService) => ({
            secret: configService.getOrThrow<string>('JWT_ACCESS_SECRET'),
          }),
        }),
      ],
      controllers: [AuthController],
      providers: [
        AuthService,
        JwtStrategy,
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
        {
          provide: RedisService,
          useValue: {
            getClient: () => redisClient,
          },
        },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        forbidUnknownValues: true,
        transform: true,
      }),
    );

    await app.init();
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  it('registers a user, logs in, reads profile, rotates refresh token, and rejects replay', async () => {
    const email = 'user@example.com';
    const password = 'Secret123!';

    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email, password })
      .expect(201);

    expect(registerResponse.body.email).toBe(email);

    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email, password })
      .expect(201);

    expect(loginResponse.body.accessToken).toBeDefined();
    expect(loginResponse.body.csrfToken).toBeDefined();

    const refreshCookie = parseSetCookieHeader(
      loginResponse.headers['set-cookie'],
      'refresh_token',
    );
    const csrfCookie = parseSetCookieHeader(
      loginResponse.headers['set-cookie'],
      'csrf_token',
    );

    expect(refreshCookie).toBeDefined();
    expect(csrfCookie).toBeDefined();
    expect(csrfCookie).toBe(loginResponse.body.csrfToken);

    const profileResponse = await request(app.getHttpServer())
      .get('/auth/profile')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .expect(200);

    expect(profileResponse.body.user.email).toBe(email);

    const refreshResponse = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', `refresh_token=${refreshCookie}; csrf_token=${csrfCookie}`)
      .set('X-CSRF-Token', loginResponse.body.csrfToken)
      .expect(201);

    expect(refreshResponse.body.accessToken).toBeDefined();

    const newRefreshCookie = parseSetCookieHeader(
      refreshResponse.headers['set-cookie'],
      'refresh_token',
    );
    expect(newRefreshCookie).toBeDefined();
    expect(newRefreshCookie).not.toBe(refreshCookie);

    const staleRefreshResponse = await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', `refresh_token=${refreshCookie}; csrf_token=${csrfCookie}`)
      .set('X-CSRF-Token', loginResponse.body.csrfToken)
      .expect(401);

    expect(staleRefreshResponse.body.message).toBeDefined();
  });

  it('rejects protected requests without bearer token', async () => {
    await request(app.getHttpServer()).get('/auth/profile').expect(401);
  });

  it('rejects refresh requests with invalid CSRF token', async () => {
    const email = 'user@example.com';
    const password = 'Secret123!';

    await request(app.getHttpServer())
      .post('/auth/register')
      .send({ email, password })
      .expect(201);

    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email, password })
      .expect(201);

    const refreshCookie = parseSetCookieHeader(
      loginResponse.headers['set-cookie'],
      'refresh_token',
    );
    const csrfCookie = parseSetCookieHeader(
      loginResponse.headers['set-cookie'],
      'csrf_token',
    );

    await request(app.getHttpServer())
      .post('/auth/refresh')
      .set('Cookie', `refresh_token=${refreshCookie}; csrf_token=${csrfCookie}`)
      .set('X-CSRF-Token', 'wrong-token')
      .expect(401);
  });
});
