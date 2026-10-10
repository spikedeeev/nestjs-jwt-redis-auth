import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import * as bcrypt from 'bcrypt';
import request from 'supertest';
import { AuthModule } from '../src/auth/auth.module';
import { PrismaService } from '../src/database/prisma.service';
import { RedisService } from '../src/redis/redis.service';

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

describe('Auth API (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;

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

    const prismaMock = {
      user: {
        create: jest.fn(async ({ data }) => ({
          id: 1,
          email: data.email,
          password: data.password,
          role: 'USER',
          createdAt: new Date(),
          updatedAt: new Date(),
        })),
        findUnique: jest.fn(async ({ where }) => {
          const email = String(where.email ?? '').toLowerCase();

          if (email === 'user@example.com') {
            return {
              id: 1,
              email,
              password: await bcrypt.hash('Secret123!', 10),
              role: 'USER',
              createdAt: new Date(),
              updatedAt: new Date(),
            };
          }

          return null;
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
          if (pattern === 'session:refresh:*') {
            if (key.startsWith('session:refresh:')) {
              keys.push(key);
            }
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
      imports: [AuthModule],
    })
      .overrideProvider(PrismaService)
      .useValue(prismaMock)
      .overrideProvider(RedisService)
      .useValue({
        getClient: () => redisClient,
      })
      .compile();

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

    prisma = moduleRef.get<PrismaService>(PrismaService);
    void prisma;
  });

  afterEach(async () => {
    await app.close();
  });

  it('should register, login, fetch profile, refresh, and reject stale refresh token', async () => {
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
    expect(refreshResponse.body.accessToken).not.toBe(
      loginResponse.body.accessToken,
    );

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

    await request(app.getHttpServer())
      .get('/auth/profile')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .expect(200);
  });

  it('should reject requests without a valid bearer token', async () => {
    await request(app.getHttpServer()).get('/auth/profile').expect(401);
  });

  it('should reject requests with invalid CSRF token during refresh', async () => {
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
