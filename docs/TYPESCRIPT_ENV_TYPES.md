# TypeScript Environment Variable Types

This guide explains the TypeScript type definitions for environment variables used in the file storage system.

## Overview

Two levels of type definitions provide full type safety:

1. **Global Types** (`src/env.d.ts`) - NodeJS.ProcessEnv declaration
2. **Local Types** (`src/infrastructure/fileStorage/index.ts`) - StorageEnv interface

## Global Environment Types

### File: `src/env.d.ts`

Extends the global `NodeJS.ProcessEnv` interface with all application environment variables.

```typescript
declare namespace NodeJS {
  interface ProcessEnv {
    STORAGE_TYPE?: "disk" | "s3";
    STORAGE_BASE_PATH?: string;
    AWS_REGION?: string;
    S3_BUCKET?: string;
    AWS_ACCESS_KEY_ID?: string;
    AWS_SECRET_ACCESS_KEY?: string;
    DATABASE_URL?: string;
    NODE_ENV?: "development" | "staging" | "production";
    PORT?: string;
  }
}
```

### Benefits

✅ **Global Scope** - Available everywhere `process.env` is used
✅ **IntelliSense** - IDE autocomplete for all env vars
✅ **Type Safety** - TypeScript catches typos and wrong types
✅ **Documentation** - JSDoc comments explain each variable

### Usage

```typescript
// Automatically typed!
const port = process.env.PORT; // string | undefined
const env = process.env.NODE_ENV; // "development" | "staging" | "production" | undefined

// TypeScript error - typo caught:
const wrong = process.env.STORGE_TYPE; // ❌ "STORGE_TYPE" is not a property
```

## Local Storage Types

### File: `src/infrastructure/fileStorage/index.ts`

Defines storage-specific environment variables with a local interface.

```typescript
interface StorageEnv {
  STORAGE_TYPE?: StorageType;
  STORAGE_BASE_PATH?: string;
  AWS_REGION?: string;
  S3_BUCKET?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
}

function getEnv(): StorageEnv {
  return process.env as unknown as StorageEnv;
}
```

### Usage in Factory

```typescript
export function createFileStorage(): IFileStorage {
  const env = getEnv(); // Fully typed as StorageEnv
  const storageType: StorageType = env.STORAGE_TYPE || "disk";

  // TypeScript knows these properties exist and their types
  const bucket = env.S3_BUCKET; // string | undefined
  const region = env.AWS_REGION || "us-east-1"; // string
  // ...
}
```

## Type-Safe Environment Access Patterns

### Pattern 1: Direct Access with Global Types

```typescript
// Best for simple, one-off access
const port = process.env.PORT;
const bucket = process.env.S3_BUCKET;
```

### Pattern 2: Typed Helper Function

```typescript
// Best for grouped variables
function getEnv(): StorageEnv {
  return process.env as unknown as StorageEnv;
}

const env = getEnv();
const bucket = env.S3_BUCKET; // Properly typed
```

### Pattern 3: Structured Configuration Object

```typescript
// Best for validation and defaults
interface Config {
  storage: {
    type: "disk" | "s3";
    diskPath: string;
    s3Bucket?: string;
    awsRegion: string;
  };
}

function getConfig(): Config {
  const env = getEnv();

  if (env.STORAGE_TYPE === "s3" && !env.S3_BUCKET) {
    throw new Error("S3_BUCKET required when STORAGE_TYPE=s3");
  }

  return {
    storage: {
      type: env.STORAGE_TYPE || "disk",
      diskPath: env.STORAGE_BASE_PATH || "./uploads",
      s3Bucket: env.S3_BUCKET,
      awsRegion: env.AWS_REGION || "us-east-1",
    },
  };
}
```

## Environment Variables Reference

### Storage Configuration

| Variable          | Type           | Default     | Required           | Notes                |
| ----------------- | -------------- | ----------- | ------------------ | -------------------- |
| STORAGE_TYPE      | "disk" \| "s3" | "disk"      | No                 | Which backend to use |
| STORAGE_BASE_PATH | string         | "./uploads" | No                 | For disk storage     |
| AWS_REGION        | string         | "us-east-1" | No                 | For S3 storage       |
| S3_BUCKET         | string         | -           | If STORAGE_TYPE=s3 | S3 bucket name       |

### AWS Credentials

| Variable              | Type   | Default | Required           | Notes                      |
| --------------------- | ------ | ------- | ------------------ | -------------------------- |
| AWS_ACCESS_KEY_ID     | string | -       | If STORAGE_TYPE=s3 | Use IAM role in production |
| AWS_SECRET_ACCESS_KEY | string | -       | If STORAGE_TYPE=s3 | Use IAM role in production |

### Application

| Variable     | Type                                       | Default       | Required | Notes                 |
| ------------ | ------------------------------------------ | ------------- | -------- | --------------------- |
| DATABASE_URL | string                                     | -             | Yes      | PostgreSQL connection |
| NODE_ENV     | "development" \| "staging" \| "production" | "development" | No       | Environment           |
| PORT         | string                                     | "3000"        | No       | Server port           |

## Type Checking Examples

### ✅ Correct Usage

```typescript
const storageType: StorageType = process.env.STORAGE_TYPE || "disk";
const bucket = process.env.S3_BUCKET;
const region = process.env.AWS_REGION || "us-east-1";
```

### ❌ Incorrect Usage

```typescript
// Typo in variable name
const type = process.env.STORGE_TYPE; // TS Error: property doesn't exist

// Wrong literal type
const env: "local" = process.env.NODE_ENV; // TS Error: type mismatch

// Missing fallback for required config
const bucket = process.env.S3_BUCKET; // TS Warning: might be undefined
```

## Validation Pattern

Type definitions don't enforce runtime constraints. Add validation:

```typescript
function validateStorageConfig(): void {
  const env = getEnv();

  if (env.STORAGE_TYPE === "s3") {
    if (!env.S3_BUCKET) {
      throw new Error("S3_BUCKET is required when STORAGE_TYPE=s3");
    }

    if (!env.AWS_ACCESS_KEY_ID && !process.env.AWS_ROLE) {
      throw new Error("AWS credentials not found");
    }
  }

  if (env.STORAGE_TYPE && !["disk", "s3"].includes(env.STORAGE_TYPE)) {
    throw new Error(`Invalid STORAGE_TYPE: ${env.STORAGE_TYPE}`);
  }
}
```

## Best Practices

### 1. Use Global Types for Simple Cases

```typescript
// ✅ Good - clear and simple
const port = process.env.PORT;
```

### 2. Use Local Helpers for Grouped Variables

```typescript
// ✅ Good - organized and type-safe
function getStorageConfig() {
  return getEnv();
}

const config = getStorageConfig();
const bucket = config.S3_BUCKET;
```

### 3. Add Runtime Validation

```typescript
// ✅ Good - types + validation
const bucket = process.env.S3_BUCKET;
if (!bucket) {
  throw new Error("S3_BUCKET required");
}
// Now TS knows bucket is not undefined
```

### 4. Use Const Assertions for Literals

```typescript
// ✅ Good - exact type
const env = "production" as const;
// env is literally "production", not string
```

### 5. Document with JSDoc

```typescript
/**
 * Storage type configuration
 * @default "disk"
 * @example
 * process.env.STORAGE_TYPE = "s3" // Use S3 backend
 */
const storageType = process.env.STORAGE_TYPE;
```

## Adding New Environment Variables

To add a new environment variable with type safety:

### Step 1: Add to Global Types

```typescript
// src/env.d.ts
declare namespace NodeJS {
  interface ProcessEnv {
    // ... existing vars ...

    /**
     * New variable description
     * @default "default-value"
     */
    NEW_VARIABLE?: string;
  }
}
```

### Step 2: Use with Type Safety

```typescript
// Now automatically typed!
const value = process.env.NEW_VARIABLE;
```

### Step 3: Add to Local Interface (if needed)

```typescript
// src/infrastructure/fileStorage/index.ts
interface StorageEnv {
  // ... existing vars ...
  NEW_VARIABLE?: string;
}
```

## TypeScript Compiler Options

Ensure `tsconfig.json` includes:

```json
{
  "compilerOptions": {
    "strict": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "moduleResolution": "node"
  },
  "include": ["src/**/*", "src/env.d.ts"]
}
```

## IDE Support

### VS Code IntelliSense

When typing `process.env.`, IntelliSense shows:

- All valid variable names
- Type information
- JSDoc descriptions
- Default values

### Type Checking in IDE

Errors appear immediately:

- ❌ Typos in variable names
- ❌ Type mismatches
- ❌ Missing required variables

## See Also

- [STORAGE_CONFIGURATION.md](./STORAGE_CONFIGURATION.md) - Environment setup
- [S3_SETUP.md](./S3_SETUP.md) - AWS configuration
- [INTEGRATION_GUIDE.md](../INTEGRATION_GUIDE.md) - Integration steps
