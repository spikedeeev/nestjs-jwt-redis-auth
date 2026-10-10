const PRIVILEGED_USER_FIELDS = new Set([
  'id',
  'role',
  'createdAt',
  'updatedAt',
  'passwordResetToken',
  'passwordResetExpiresAt',
  'isAdmin',
  'permissions',
  'emailVerified',
]);

export function sanitizeUserInput<T extends Record<string, unknown>>(
  input: T,
  allowedFields: string[],
): Partial<T> {
  const allowedSet = new Set(allowedFields);

  return Object.fromEntries(
    Object.entries(input).filter(([key, value]) => {
      if (value === undefined) {
        return false;
      }

      if (PRIVILEGED_USER_FIELDS.has(key)) {
        return false;
      }

      return allowedSet.has(key);
    }),
  ) as Partial<T>;
}

export function stripPrivilegedFields<T extends Record<string, unknown>>(
  input: T,
): Partial<T> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || PRIVILEGED_USER_FIELDS.has(key)) {
      continue;
    }

    sanitized[key] = value;
  }

  return sanitized as Partial<T>;
}
