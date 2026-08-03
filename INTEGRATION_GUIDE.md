# File Management Integration Guide

Quick start guide to integrate the file management system into your project.

**Storage Backends:**

- 🖥️ **Disk Storage** (default) - Local filesystem, great for development
- ☁️ **AWS S3** - Cloud storage, recommended for production

See [STORAGE_CONFIGURATION.md](./docs/STORAGE_CONFIGURATION.md) for storage setup details.

## Step 1: Update Database Schema Exports

Edit `src/infrastructure/schema/index.ts`:

```typescript
// Add this line to export the files table and relations
export { files, fileCategories, fileMetadata } from "./files";

// If you have relations defined, add:
export const filesRelations = relations(files, {
  tenant: () => relations(tenants),
  // Add other relations as needed
});
```

## Step 2: Update Database Context

Edit `src/infrastructure/dbContext.ts` to include files relations:

```typescript
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema/index"; // Import all relations

const queryClient = postgres(process.env.DATABASE_URL);

const dbContext = drizzle({
  client: queryClient,
  schema, // Add schema with relations
});

export default dbContext;
```

## Step 3: Create Drizzle Migration

```bash
# Generate migration for new files table
npm run db:generate

# Apply the migration
npm run db:migrate
```

If you don't have these npm scripts, add them to `package.json`:

```json
{
  "scripts": {
    "db:generate": "drizzle-kit generate:pg --config=drizzle.config.ts",
    "db:migrate": "drizzle-kit migrate:pg --config=drizzle.config.ts"
  }
}
```

And create `drizzle.config.ts`:

```typescript
import type { Config } from "drizzle-kit";

export default {
  schema: "./src/infrastructure/schema",
  out: "./drizzle",
  driver: "pg",
  dbCredentials: {
    connectionString: process.env.DATABASE_URL || "",
  },
} satisfies Config;
```

## Step 4: Mount File API Routes

Edit `src/main.ts`:

```typescript
import { Hono } from "hono";
import { contextStorage } from "hono/context-storage";
import { logger } from "hono/logger";
import { trimTrailingSlash } from "hono/trailing-slash";

import conditionsApi from "#rest-api/conditions/index";
import locationsApi from "#rest-api/locations/index";
import filesApi from "#rest-api/files/index"; // Add this

type Env = {
  Variables: {
    tenantId: string;
  };
};

const app = new Hono<Env>({
  strict: true,
});

app.use(logger());
app.use(trimTrailingSlash());
app.use(contextStorage());

app.use(async (c, next) => {
  c.set("tenantId", "01976ed4-b771-700a-b1e8-a1e898e5451d");
  await next();
});

app.route("/conditions", conditionsApi);
app.route("/locations", locationsApi);
app.route("/files", filesApi); // Add this line

export default app;
```

## Step 5: Configure Storage

### Option A: Disk Storage (Development)

Create `.env` file:

```bash
# Disk storage (default)
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

Create the uploads directory:

```bash
mkdir -p uploads
chmod 755 uploads
```

### Option B: AWS S3 (Production)

For S3 storage, see detailed setup in [S3_SETUP.md](./docs/S3_SETUP.md).

Quick setup:

1. Create S3 bucket and IAM user
2. Install AWS SDK: `npm install @aws-sdk/client-s3`
3. Configure `.env`:

```bash
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

4. Restart application

The API usage is identical for both backends - no code

## Step 6: Verify Integration

### Test the API

```bash
# Start the server
npm run dev

# In another terminal, test upload
curl -X POST \
  -F "file=@test.pdf" \
  http://localhost:3000/files

# List files
curl http://localhost:3000/files

# Download file (replace {fileId} with actual ID)
curl http://localhost:3000/files/{fileId} -o output.pdf

# Get metadata
curl http://localhost:3000/files/{fileId}/metadata

# Delete file
curl -X DELETE http://localhost:3000/files/{fileId}
```

## Step 7: Add Input Validation

Enhance the REST API with validation. Edit `src/rest-api/files/index.ts`:

```typescript
import { Hono } from "hono";
import { z } from "zod";

const filesApi = new Hono();

// Validation schema
const uploadSchema = z.object({
  // File will be validated in handler
});

const listQuerySchema = z.object({
  search: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

// Add validation middleware
filesApi.post("/", async (c) => {
  const tenantId = currentTenantId();
  const formData = await c.req.formData();
  const file = formData.get("file");

  // Validate file exists
  if (!(file instanceof File)) {
    return c.json({ error: "No file provided" }, 400);
  }

  // Validate file size (100MB max)
  const MAX_SIZE = 100 * 1024 * 1024;
  if (file.size > MAX_SIZE) {
    return c.json({ error: `File exceeds maximum size of ${MAX_SIZE} bytes` }, 400);
  }

  // Validate MIME type (optional)
  const allowedMimes = ["application/pdf", "image/jpeg", "image/png", "text/plain"];
  if (!allowedMimes.includes(file.type)) {
    return c.json({ error: `File type not allowed: ${file.type}` }, 400);
  }

  const buffer = Buffer.from(await file.arrayBuffer());

  try {
    const result = await uploadFileCommand({
      tenantId,
      fileName: file.name,
      mimeType: file.type,
      buffer,
    });

    return c.json(result, 201);
  } catch (error) {
    return c.json({ error: String(error) }, 500);
  }
});

// ... rest of the API
```

## Step 8: Create Test File

Create `src/rest-api/files/index.spec.ts`:

```typescript
import { test } from "node:test";
import { strict as assert } from "node:assert";

test("File Upload, List, and Delete", async () => {
  // Test upload
  const uploadResult = await uploadFileCommand({
    tenantId: "test-tenant",
    fileName: "test.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("test content"),
  });

  assert(uploadResult.id);
  assert.equal(uploadResult.name, "test.txt");

  // Test list
  const listResult = await listFilesQuery({
    tenantId: "test-tenant",
  });

  assert(listResult.files.length > 0);

  // Test get
  const getResult = await getFileQuery(uploadResult.id, "test-tenant", false);

  assert.equal(getResult.name, "test.txt");

  // Test delete
  const deleteResult = await deleteFileCommand(uploadResult.id, "test-tenant");

  assert.equal(deleteResult.success, true);
});
```

Run tests:

```bash
npm test
```

## Step 9: Update Environment Configuration

If deploying to Lambda, update `src/lambda-handler.ts`:

```typescript
import app from "#main";

export const handler = app.fetch;
```

If using Node.js server, update `src/node-handler.ts`:

```typescript
import { serve } from "@hono/node-server";
import app from "#main";

const port = process.env.PORT || 3000;

serve({
  fetch: app.fetch,
  port,
});

console.log(`Server running on http://localhost:${port}`);
```

## Step 10: Build and Test

```bash
# Build the project
npm run build

# Run tests
npm test

# Start development server
npm run dev

# Format code
npm run format

# Lint
npm run lint
```

## Troubleshooting

### Database connection error

```
Error: connect ECONNREFUSED
```

Solution:

- Verify DATABASE_URL is set
- Check PostgreSQL is running
- Verify database exists

### File not found errors

```
Error: File not found
```

Solution:

- Check file exists in database
- Check file exists at storage path
- Verify tenant context is correct
- Check permissions on uploads directory

### Storage path errors

```
Error: Invalid file path: directory traversal detected
```

Solution:

- This is a security feature
- Verify file names don't contain `../`
- Use URL encoding for special characters

### Permission denied

```
Error: EACCES: permission denied
```

Solution:

```bash
chmod 755 uploads
chmod 644 uploads/*
```

## Next Steps

1. **Implement tests** - Create unit and integration tests
2. **Add input validation** - Implement file type/size restrictions
3. **Setup monitoring** - Add logging for file operations
4. **Configure backups** - Implement file backup strategy
5. **Scale storage** - Consider S3 or cloud storage for production
6. **Implement sharing** - Add temporary share links (see advanced docs)
7. **Add versioning** - Track file history
8. **Setup CDN** - For efficient file distribution

## Documentation Files

- **[FILE_MANAGEMENT.md](./docs/FILE_MANAGEMENT.md)** - Complete implementation guide
- **[FILE_MANAGEMENT_ADVANCED.md](./docs/FILE_MANAGEMENT_ADVANCED.md)** - Advanced patterns
- **[FILE_MANAGEMENT_ARCHITECTURE.md](./docs/FILE_MANAGEMENT_ARCHITECTURE.md)** - Architecture diagrams
- **[FILE_MANAGEMENT_CHECKLIST.md](./docs/FILE_MANAGEMENT_CHECKLIST.md)** - Implementation checklist

## Quick Reference

### File Paths

```
src/
├── core/entities/
│   └── file.ts
├── infrastructure/
│   ├── fileStorage/
│   │   ├── storage.ts
│   │   └── diskStorage.ts
│   └── schema/
│       └── files.ts
├── application/files/
│   ├── uploadFileCommand.ts
│   ├── getFileQuery.ts
│   ├── listFilesQuery.ts
│   └── deleteFileCommand.ts
└── rest-api/files/
    └── index.ts
```

### Core Operations

```typescript
// Upload
const file = await uploadFileCommand({
  tenantId: string,
  fileName: string,
  mimeType: string,
  buffer: Buffer,
});

// List
const result = await listFilesQuery({
  tenantId: string,
  search?: string,
  limit?: number,
  offset?: number,
});

// Get
const file = await getFileQuery(
  fileId: string,
  tenantId: string,
  includeContent?: boolean,
);

// Delete
const result = await deleteFileCommand(
  fileId: string,
  tenantId: string,
);
```

### REST Endpoints

```bash
GET    /files                        # List files
POST   /files                        # Upload file
GET    /files/:fileId                # Download file
GET    /files/:fileId/metadata       # Get metadata
DELETE /files/:fileId                # Delete file
```

## Support & Questions

For detailed information, see:

- Architecture overview: `docs/FILE_MANAGEMENT_ARCHITECTURE.md`
- Implementation details: `docs/FILE_MANAGEMENT.md`
- Advanced patterns: `docs/FILE_MANAGEMENT_ADVANCED.md`
- Integration checklist: `docs/FILE_MANAGEMENT_CHECKLIST.md`
