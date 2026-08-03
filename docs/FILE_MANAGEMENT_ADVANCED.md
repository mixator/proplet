# Advanced File Management Patterns

This document covers advanced patterns and implementations for the file management system.

## 1. Stream Processing for Large Files

### Memory-Efficient Upload

```typescript
// src/application/files/streamUploadCommand.ts
import { Readable } from "stream";
import crypto from "crypto";

export const streamUploadCommand = async (
  tenantId: string,
  fileName: string,
  mimeType: string,
  stream: Readable,
  maxSize: number = 100 * 1024 * 1024, // 100MB
) => {
  const fileId = crypto.randomUUID();
  const storagePath = `${tenantId}/${fileId}/${fileName}`;

  let size = 0;
  const hash = crypto.createHash("sha256");

  try {
    // Stream directly to storage without buffering
    await fileStorage.saveFileStream(storagePath, stream, {
      onData: (chunk) => {
        size += chunk.length;
        hash.update(chunk);

        if (size > maxSize) {
          throw new Error(`File exceeds maximum size of ${maxSize} bytes`);
        }
      },
    });

    // Record in database with hash for integrity checking
    const result = await dbContext
      .insert(files)
      .values({
        id: fileId,
        name: fileName,
        mimeType,
        size,
        path: storagePath,
        tenantId,
        checksum: hash.digest("hex"), // Add to schema
      })
      .returning();

    return result[0];
  } catch (error) {
    await fileStorage.deleteFile(storagePath).catch(() => {});
    throw error;
  }
};
```

### Memory-Efficient Download

```typescript
// src/rest-api/files/download-stream.ts
filesApi.get("/:fileId/stream", async (c) => {
  const tenantId = currentTenantId();
  const fileId = c.req.param("fileId");

  try {
    const fileRecord = await getFileQuery(fileId, tenantId, false);

    c.header("Content-Type", fileRecord.mimeType);
    c.header("Content-Length", fileRecord.size.toString());
    c.header("Content-Disposition", `attachment; filename="${fileRecord.name}"`);

    // Stream file directly to response
    const stream = await fileStorage.readFileStream(fileRecord.path);
    return c.body(stream);
  } catch (error) {
    return c.json({ error: String(error) }, 404);
  }
});
```

### Updated Storage Interface

```typescript
// Add to src/infrastructure/fileStorage/storage.ts
export interface IFileStorage {
  // ... existing methods ...

  /**
   * Save file from a readable stream
   */
  saveFileStream(
    path: string,
    stream: Readable,
    options?: {
      onData?: (chunk: Buffer) => void;
      maxSize?: number;
    },
  ): Promise<void>;

  /**
   * Read file as a readable stream
   */
  readFileStream(path: string): Promise<Readable>;
}
```

## 2. File Validation and Processing

### Content Validation

```typescript
// src/infrastructure/fileStorage/validators.ts
import { createReadStream } from "fs";

export const FILE_RESTRICTIONS = {
  pdf: { mimeType: "application/pdf", maxSize: 50 * 1024 * 1024 },
  image: {
    mimeType: ["image/jpeg", "image/png", "image/webp"],
    maxSize: 10 * 1024 * 1024,
  },
  document: {
    mimeType: [
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ],
    maxSize: 25 * 1024 * 1024,
  },
} as const;

export function validateFile(
  fileName: string,
  mimeType: string,
  size: number,
  category: keyof typeof FILE_RESTRICTIONS = "pdf",
): { valid: boolean; error?: string } {
  const restrictions = FILE_RESTRICTIONS[category];

  if (size > restrictions.maxSize) {
    return { valid: false, error: `File exceeds maximum size of ${restrictions.maxSize} bytes` };
  }

  const allowedTypes = Array.isArray(restrictions.mimeType)
    ? restrictions.mimeType
    : [restrictions.mimeType];

  if (!allowedTypes.includes(mimeType)) {
    return {
      valid: false,
      error: `Invalid file type. Allowed: ${allowedTypes.join(", ")}`,
    };
  }

  return { valid: true };
}

export async function verifyFileIntegrity(
  filePath: string,
  expectedChecksum: string,
): Promise<boolean> {
  const crypto = require("crypto");
  const hash = crypto.createHash("sha256");
  const stream = createReadStream(filePath);

  for await (const chunk of stream) {
    hash.update(chunk);
  }

  return hash.digest("hex") === expectedChecksum;
}
```

## 3. Batch Operations

### Batch Upload

```typescript
// src/application/files/batchUploadCommand.ts
export const batchUploadCommand = async (
  tenantId: string,
  files: Array<{ name: string; mimeType: string; buffer: Buffer }>,
) => {
  const results = await Promise.allSettled(
    files.map((file) =>
      uploadFileCommand({
        tenantId,
        fileName: file.name,
        mimeType: file.mimeType,
        buffer: file.buffer,
      }),
    ),
  );

  return {
    successful: results
      .filter((r) => r.status === "fulfilled")
      .map((r) => (r as PromiseFulfilledResult<any>).value),
    failed: results
      .filter((r) => r.status === "rejected")
      .map((r, i) => ({
        index: i,
        fileName: files[i].name,
        error: (r as PromiseRejectedResult).reason,
      })),
  };
};
```

### Batch Delete

```typescript
// src/application/files/batchDeleteCommand.ts
export const batchDeleteCommand = async (fileIds: string[], tenantId: string) => {
  const results = await Promise.allSettled(fileIds.map((id) => deleteFileCommand(id, tenantId)));

  return {
    deleted: results.filter((r) => r.status === "fulfilled").length,
    failed: results.filter((r) => r.status === "rejected").length,
    errors: results
      .filter((r) => r.status === "rejected")
      .map((r) => (r as PromiseRejectedResult).reason),
  };
};
```

## 4. File Organization and Tagging

### Enhanced Schema

```typescript
// Add to src/infrastructure/schema/files.ts
export const fileCategories = pgTable("file_categories", {
  id: uuid().primaryKey().defaultRandom(),
  fileId: uuid()
    .notNull()
    .references(() => files.id, { onDelete: "cascade" }),
  category: text().notNull(), // "invoice", "receipt", "document", etc.
  createdAt: timestamp().defaultNow().notNull(),
});

export const fileMetadata = pgTable("file_metadata", {
  id: uuid().primaryKey().defaultRandom(),
  fileId: uuid()
    .notNull()
    .references(() => files.id, { onDelete: "cascade" }),
  key: text().notNull(),
  value: text().notNull(),
  createdAt: timestamp().defaultNow().notNull(),
});
```

### Categorized Upload

```typescript
// src/application/files/uploadCategorizedFileCommand.ts
export const uploadCategorizedFileCommand = async (
  tenantId: string,
  fileName: string,
  mimeType: string,
  buffer: Buffer,
  category: string,
  metadata?: Record<string, string>,
) => {
  // Upload base file
  const file = await uploadFileCommand({
    tenantId,
    fileName,
    mimeType,
    buffer,
  });

  // Add category
  await dbContext.insert(fileCategories).values({
    fileId: file.id,
    category,
  });

  // Add metadata tags
  if (metadata) {
    await dbContext.insert(fileMetadata).values(
      Object.entries(metadata).map(([key, value]) => ({
        fileId: file.id,
        key,
        value,
      })),
    );
  }

  return file;
};
```

## 5. Temporary Share Links

### Generate Secure Share Token

```typescript
// src/infrastructure/fileStorage/shareTokens.ts
import crypto from "crypto";

const SHARE_TOKENS = new Map<
  string,
  {
    fileId: string;
    tenantId: string;
    expiresAt: Date;
    maxDownloads?: number;
    downloadCount: number;
  }
>();

export function generateShareToken(
  fileId: string,
  tenantId: string,
  expiresIn: number = 24 * 60 * 60 * 1000, // 24 hours
  maxDownloads?: number,
): string {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + expiresIn);

  SHARE_TOKENS.set(token, {
    fileId,
    tenantId,
    expiresAt,
    maxDownloads,
    downloadCount: 0,
  });

  return token;
}

export function validateShareToken(token: string): {
  valid: boolean;
  fileId?: string;
  tenantId?: string;
} {
  const share = SHARE_TOKENS.get(token);

  if (!share) {
    return { valid: false };
  }

  if (share.expiresAt < new Date()) {
    SHARE_TOKENS.delete(token);
    return { valid: false };
  }

  if (share.maxDownloads && share.downloadCount >= share.maxDownloads) {
    return { valid: false };
  }

  share.downloadCount++;
  return { valid: true, fileId: share.fileId, tenantId: share.tenantId };
}
```

### Share Token API

```typescript
// Add to src/rest-api/files/index.ts

// Generate share link
filesApi.post("/:fileId/share", async (c) => {
  const tenantId = currentTenantId();
  const fileId = c.req.param("fileId");
  const body = await c.req.json();
  const { expiresIn = 24 * 60 * 60 * 1000, maxDownloads } = body;

  // Verify file exists
  await getFileQuery(fileId, tenantId, false);

  const token = generateShareToken(fileId, tenantId, expiresIn, maxDownloads);

  return c.json({
    shareLink: `${c.req.url.split("/files")[0]}/files/shared/${token}`,
    token,
    expiresAt: new Date(Date.now() + expiresIn),
  });
});

// Download via share token (no auth required)
filesApi.get("/shared/:token", async (c) => {
  const token = c.req.param("token");
  const share = validateShareToken(token);

  if (!share.valid) {
    return c.json({ error: "Invalid or expired share link" }, 401);
  }

  try {
    const file = await getFileQuery(share.fileId!, share.tenantId!, true);

    if (!file.content) {
      return c.json({ error: "File not found" }, 404);
    }

    c.header("Content-Type", file.mimeType);
    c.header("Content-Disposition", `attachment; filename="${file.name}"`);
    return c.body(file.content);
  } catch (error) {
    return c.json({ error: String(error) }, 404);
  }
});
```

## 6. Async Processing Queue

### File Processing Pipeline

```typescript
// src/infrastructure/fileStorage/processingQueue.ts
import { EventEmitter } from "events";

export type FileProcessor = (fileId: string, tenantId: string, filePath: string) => Promise<void>;

class FileProcessingQueue extends EventEmitter {
  private queue: Array<{
    fileId: string;
    tenantId: string;
    filePath: string;
    processor: FileProcessor;
  }> = [];

  private processing = false;
  private concurrency = 3;
  private activeCount = 0;

  enqueue(fileId: string, tenantId: string, filePath: string, processor: FileProcessor) {
    this.queue.push({ fileId, tenantId, filePath, processor });
    this.process();
  }

  private async process() {
    if (this.processing || this.activeCount >= this.concurrency) {
      return;
    }

    this.processing = true;

    while (this.queue.length > 0 && this.activeCount < this.concurrency) {
      const item = this.queue.shift();
      if (!item) break;

      this.activeCount++;

      try {
        await item.processor(item.fileId, item.tenantId, item.filePath);
        this.emit("completed", item.fileId);
      } catch (error) {
        this.emit("error", { fileId: item.fileId, error });
      } finally {
        this.activeCount--;
      }
    }

    this.processing = false;
  }
}

export const fileQueue = new FileProcessingQueue();

// Example: Image thumbnail generator
export async function generateThumbnail(fileId: string, tenantId: string, filePath: string) {
  // Use sharp or ffmpeg to generate thumbnail
  // Save thumbnail to {tenantId}/{fileId}/thumbnail.jpg
}
```

## 7. Audit Logging

### Enhanced Audit Trail

```typescript
// src/infrastructure/schema/fileAuditLog.ts
export const fileAuditLog = pgTable("file_audit_log", {
  id: uuid().primaryKey().defaultRandom(),
  fileId: uuid().references(() => files.id),
  tenantId: uuid().notNull(),
  action: text().notNull(), // "upload", "download", "delete", "share"
  userId: uuid(), // If you track users
  ipAddress: text(),
  userAgent: text(),
  details: jsonb(), // Additional context
  createdAt: timestamp().defaultNow().notNull(),
});

export async function logFileAction(
  action: string,
  fileId: string,
  tenantId: string,
  context?: Record<string, any>,
) {
  await dbContext.insert(fileAuditLog).values({
    action,
    fileId,
    tenantId,
    details: context,
  });
}
```

## 8. Storage Backend Switching

### Environment-Based Storage Factory

```typescript
// src/infrastructure/fileStorage/index.ts
import { IFileStorage } from "./storage";
import { DiskStorage } from "./diskStorage";

export function createFileStorage(): IFileStorage {
  const storageType = process.env.STORAGE_TYPE || "disk";

  switch (storageType) {
    case "s3":
      // return new S3Storage();
      throw new Error("S3 storage not yet implemented");
    case "azure":
      // return new AzureStorage();
      throw new Error("Azure storage not yet implemented");
    case "disk":
    default:
      return new DiskStorage(process.env.STORAGE_PATH || "./uploads");
  }
}

export const fileStorage = createFileStorage();
```

## Performance Tips

1. **Use streaming for files > 1MB**
2. **Enable gzip compression for text files**
3. **Implement CDN for frequently accessed files**
4. **Use database connection pooling**
5. **Cache file metadata with Redis**
6. **Implement rate limiting on uploads**
7. **Use ETag headers for caching**
8. **Parallel process batch operations**

## Scalability Considerations

1. **Distributed Storage**: Use S3 or equivalent
2. **Database Sharding**: Partition by tenantId
3. **Message Queue**: Offload processing to background jobs
4. **Load Balancing**: Distribute upload/download traffic
5. **File Replication**: For disaster recovery
6. **Archive Strategy**: Move old files to cold storage
