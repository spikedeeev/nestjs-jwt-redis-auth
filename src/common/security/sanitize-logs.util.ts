const SENSITIVE_KEY_PATTERN =
  /(password|passwd|pwd|secret|token|jwt|authorization|cookie|set-cookie|refresh[_-]?token|access[_-]?token|api[_-]?key|private[_-]?key)/i;

const JWT_LIKE_PATTERN = /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/i;
const BEARER_PATTERN = /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi;

function redactSensitiveValue(value: string): string {
  if (!value) {
    return value;
  }

  let result = value;

  if (JWT_LIKE_PATTERN.test(result)) {
    result = result.replace(JWT_LIKE_PATTERN, '[JWT_REDACTED]');
  }

  if (BEARER_PATTERN.test(result)) {
    result = result.replace(BEARER_PATTERN, 'Bearer [REDACTED]');
  }

  return result.replace(
    /(authorization|cookie|set-cookie|secret|refresh[_-]?token|access[_-]?token|jwt|api[_-]?key|private[_-]?key)\s*[:=]\s*([^,;\s]+)/gi,
    '$1=[REDACTED]',
  );
}

export function sanitizeForLogs<T>(value: T): T {
  if (typeof value === 'string') {
    return redactSensitiveValue(value) as T;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeForLogs(item)) as T;
  }

  if (value && typeof value === 'object') {
    const sanitized: Record<string, unknown> = {};

    for (const [key, entryValue] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        sanitized[key] = '[REDACTED]';
        continue;
      }

      sanitized[key] = sanitizeForLogs(entryValue);
    }

    return sanitized as T;
  }

  return value;
}

export function sanitizeErrorMessage(value: unknown): string {
  const message = String(value ?? '');
  return redactSensitiveValue(message);
}
