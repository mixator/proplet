# Environment Variable Validation

This document explains the Zod-based environment variable validation system that provides early fail detection at application startup.

## Overview

The application validates all environment variables at startup using Zod. If any required variables are missing or invalid, the application fails immediately with clear error messages.

## Architecture

```
Application Startup
    ↓
validateEnv() called in main.ts
    ↓
Zod schema validation
    ↓
Conditional validation (S3 rules)
    ↓
Valid: Continue startup → logEnvironment()
Invalid: Throw error → Exit with message
```

## Implementation Files

### `src/infrastructure/env.ts`

Zod schema and validation logic:

```typescript
// Define validation schema
const envSchema = z.object({
  STORAGE_TYPE: z.enum(["disk", "s3"]).default("disk"),
  DATABASE_URL: z.string().url(),
  // ... more fields
});

// Add conditional validation
const refinedEnvSchema = envSchema.refine(
  (env) => {
    if (env.STORAGE_TYPE === "s3" && !env.S3_BUCKET) {
      return false;
    }
    return true;
  },
  {
    message: "S3_BUCKET is required when STORAGE_TYPE=s3",
    path: ["S3_BUCKET"],
  },
);

// Export type-safe environment
export type Environment = z.infer<typeof refinedEnvSchema>;

// Validation function
export function validateEnv(): Environment {
  const result = refinedEnvSchema.safeParse(process.env);
  if (!result.success) {
    // Detailed error formatting
    throw new Error(`❌ Environment validation failed:\n${errors}`);
  }
  return result.data;
}
```

### `src/main.ts`

Environment validation at startup:

```typescript
import { validateEnv, logEnvironment } from "#infrastructure/env";

// Validate environment variables at startup
// This will throw and exit if any required variables are missing
validateEnv();
logEnvironment();

// ... rest of application
```

## Validation Rules

### Storage Configuration

| Variable          | Type           | Default     | Required           | Validation           |
| ----------------- | -------------- | ----------- | ------------------ | -------------------- |
| STORAGE_TYPE      | "disk" \| "s3" | "disk"      | No                 | Must be valid enum   |
| STORAGE_BASE_PATH | string         | "./uploads" | No                 | Must be valid path   |
| AWS_REGION        | string         | "us-east-1" | No                 | Must be valid string |
| S3_BUCKET         | string         | -           | If STORAGE_TYPE=s3 | Custom validation    |

### AWS Credentials

| Variable              | Type   | Default | Required | Validation           |
| --------------------- | ------ | ------- | -------- | -------------------- |
| AWS_ACCESS_KEY_ID     | string | -       | No       | Must be valid string |
| AWS_SECRET_ACCESS_KEY | string | -       | No       | Must be valid string |

### Database

| Variable     | Type   | Default | Required | Validation        |
| ------------ | ------ | ------- | -------- | ----------------- |
| DATABASE_URL | string | -       | **Yes**  | Must be valid URL |

### Application

| Variable | Type   | Default       | Required | Validation                          |
| -------- | ------ | ------------- | -------- | ----------------------------------- |
| NODE_ENV | enum   | "development" | No       | development, staging, or production |
| PORT     | number | 3000          | No       | Integer between 0 and 65535         |

## Conditional Validation

### S3 Configuration Rule

When `STORAGE_TYPE=s3`, the `S3_BUCKET` variable becomes **required**:

```typescript
refinedEnvSchema.refine(
  (env) => {
    if (env.STORAGE_TYPE === "s3" && !env.S3_BUCKET) {
      return false;
    }
    return true;
  },
  {
    message: "S3_BUCKET is required when STORAGE_TYPE=s3",
    path: ["S3_BUCKET"],
  },
);
```

**Error Message (if missing):**

```
❌ Environment validation failed:
  • S3_BUCKET: S3_BUCKET is required when STORAGE_TYPE=s3
```

## Error Messages

### Missing Required Variable

```
❌ Environment validation failed:
  • DATABASE_URL: Required
```

### Invalid Type

```
❌ Environment validation failed:
  • PORT: Expected number, received string
```

### Invalid Enum Value

```
❌ Environment validation failed:
  • NODE_ENV: Invalid enum value. Expected 'development' | 'staging' | 'production'
```

### Invalid URL

```
❌ Environment validation failed:
  • DATABASE_URL: Invalid url
```

### Conditional Validation

```
❌ Environment validation failed:
  • S3_BUCKET: S3_BUCKET is required when STORAGE_TYPE=s3
```

## Usage Examples

### Valid Configuration (Disk Storage)

```bash
# .env
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
DATABASE_URL=postgres://user:pass@localhost:5432/db
NODE_ENV=development
PORT=3000
```

Result: ✓ Application starts successfully

### Valid Configuration (S3 Storage)

```bash
# .env
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=my-bucket
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
DATABASE_URL=postgres://user:pass@localhost:5432/db
```

Result: ✓ Application starts successfully

### Invalid Configuration (Missing S3_BUCKET)

```bash
# .env
STORAGE_TYPE=s3
DATABASE_URL=postgres://user:pass@localhost:5432/db
# Missing S3_BUCKET!
```

Result: ✗ Application fails with error:

```
❌ Environment validation failed:
  • S3_BUCKET: S3_BUCKET is required when STORAGE_TYPE=s3
```

### Invalid Configuration (Missing DATABASE_URL)

```bash
# .env
STORAGE_TYPE=disk
# Missing DATABASE_URL!
```

Result: ✗ Application fails with error:

```
❌ Environment validation failed:
  • DATABASE_URL: Required
```

## Type Safety

The validated environment is fully type-safe:

```typescript
import { env } from "#infrastructure/env";

// All properties are properly typed
const storageType = env.STORAGE_TYPE; // "disk" | "s3"
const port = env.PORT; // number
const nodeEnv = env.NODE_ENV; // "development" | "staging" | "production"

// TypeScript catches errors:
const invalid = env.INVALID_VAR; // ❌ Property does not exist
```

## Startup Behavior

### On Valid Environment

1. `validateEnv()` called
2. Zod schema validation passes
3. Validated environment returned
4. `logEnvironment()` displays summary
5. Application continues startup

**Console Output:**

```
✓ Environment validated successfully:
{
  "STORAGE_TYPE": "disk",
  "STORAGE_BASE_PATH": "./uploads",
  "AWS_REGION": "us-east-1",
  "DATABASE_URL": "***",
  "NODE_ENV": "development",
  "PORT": 3000
}
```

### On Invalid Environment

1. `validateEnv()` called
2. Zod schema validation fails
3. Detailed error message generated
4. Error thrown
5. Process exits with code 1

**Console Output:**

```
❌ Environment validation failed:
  • DATABASE_URL: Required
  • PORT: Expected number, received string

Please check your .env file and try again.
```

## Adding New Environment Variables

To add a new validated environment variable:

### Step 1: Update Zod Schema

```typescript
// src/infrastructure/env.ts
const envSchema = z.object({
  // ... existing fields ...

  NEW_VARIABLE: z.string().default("default-value").describe("Description of the variable"),
});
```

### Step 2: Update Type Declaration

```typescript
// src/env.d.ts
declare namespace NodeJS {
  interface ProcessEnv {
    NEW_VARIABLE?: string;
  }
}
```

### Step 3: Use in Application

```typescript
import { env } from "#infrastructure/env";

const value = env.NEW_VARIABLE; // Fully typed!
```

## Environment Logging

The `logEnvironment()` function displays validated variables without sensitive data:

```typescript
export function logEnvironment(): void {
  const safe = {
    STORAGE_TYPE: env.STORAGE_TYPE,
    // Sensitive values replaced with ***
    S3_BUCKET: env.S3_BUCKET ? "***" : undefined,
    DATABASE_URL: env.DATABASE_URL ? "***" : undefined,
    NODE_ENV: env.NODE_ENV,
    PORT: env.PORT,
  };

  console.log("✓ Environment validated successfully:");
  console.log(JSON.stringify(safe, null, 2));
}
```

## Best Practices

### 1. Validate Early

Environment validation happens at the very top of `main.ts`:

```typescript
// Do this first!
validateEnv();
logEnvironment();

// Then setup application
const app = new Hono();
```

### 2. Use Validated Environment

Always import validated environment from infrastructure:

```typescript
// ✅ Good
import { env } from "#infrastructure/env";
const bucket = env.S3_BUCKET;

// ❌ Avoid
const bucket = process.env.S3_BUCKET; // Not type-safe
```

### 3. Set Sensible Defaults

```typescript
STORAGE_TYPE: z
  .enum(["disk", "s3"])
  .default("disk"), // Default to disk if not specified

NODE_ENV: z
  .enum(["development", "staging", "production"])
  .default("development"), // Default to development
```

### 4. Add Descriptions

```typescript
DATABASE_URL: z
  .string()
  .url()
  .describe("PostgreSQL connection URL"), // Help users understand
```

### 5. Use Conditional Validation

For complex rules, use `.refine()`:

```typescript
refinedEnvSchema.refine(
  (env) => {
    // Your logic
    return isValid;
  },
  {
    message: "Clear error message",
    path: ["FIELD_NAME"],
  },
);
```

## Troubleshooting

### Application Won't Start

Check the error message:

```bash
# Run the application
npm run dev

# Check the output for validation errors
# Example output:
# ❌ Environment validation failed:
#   • DATABASE_URL: Required
```

**Solution:** Add the missing variable to `.env`

### "Environment not defined" Error

Make sure you import from the right place:

```typescript
// ✅ Correct
import { env } from "#infrastructure/env";

// ❌ Wrong
import { env } from "#infrastructure/fileStorage";
```

### Sensitive Data in Logs

The `logEnvironment()` function automatically masks sensitive values:

- S3_BUCKET: Shown as `***` if set
- DATABASE_URL: Shown as `***` if set
- AWS keys: Never logged

## See Also

- [TYPESCRIPT_ENV_TYPES.md](./TYPESCRIPT_ENV_TYPES.md) - TypeScript environment types
- [STORAGE_CONFIGURATION.md](./STORAGE_CONFIGURATION.md) - Storage setup
- [S3_SETUP.md](./S3_SETUP.md) - AWS S3 configuration
