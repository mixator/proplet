# File Management Implementation Guide

This document outlines the file management system implementation for the Proplet project.

## Architecture Overview

The file management system follows the project's **layered architecture**:

```
REST API Layer (HTTP endpoints)
    ↓
Application Layer (Business logic/Commands/Queries)
    ↓
Infrastructure Layer (Storage, Database, External services)
    ↓
Core Layer (Domain entities)
```

## Components

### 1. Core Layer (`src/core/entities/file.ts`)

Defines the `File` domain entity with validation using Zod:

- `id`: Unique identifier (UUID)
- `name`: Original filename
- `mimeType`: MIME type of the file
- `size`: File size in bytes
- `path`: Relative storage path
- `createdAt`, `updatedAt`: Timestamps
- `tenantId`: Multi-tenant isolation

### 2. Infrastructure Layer

#### Database Schema (`src/infrastructure/schema/files.ts`)

PostgreSQL table with:

- File metadata storage
- Foreign key relationship to `tenants` table
- Timestamps for audit trails

#### Storage Interface (`src/infrastructure/fileStorage/storage.ts`)

Abstract `IFileStorage` interface providing:

- **File Operations**: save, read, delete, exists
- **Metadata**: size, modification time
- **Directory Operations**: list files, pattern matching
- **File Manipulation**: move, copy
- **Extensibility**: Easy to implement S3, Azure, or other providers

#### Disk Storage Implementation (`src/infrastructure/fileStorage/diskStorage.ts`)

Node.js filesystem implementation:

- **Security**: Directory traversal attack prevention
- **Error Handling**: Graceful failure recovery
- **Metadata Support**: File stats and timestamps
- **Pattern Matching**: Glob-like file filtering
- **Atomic Operations**: Batch operations with rollback

### 3. Application Layer (`src/application/files/`)

Contains business logic following CQRS pattern:

#### `uploadFileCommand.ts`

- Accepts file buffer, metadata
- Generates unique storage path: `{tenantId}/{fileId}/{fileName}`
- Atomic operation: save to storage → record in DB
- Rollback on failure (cleanup storage if DB fails)

#### `getFileQuery.ts`

- Retrieve file metadata from database
- Optional: Load file content from storage
- Tenant isolation enforcement
- Error handling for missing/corrupt files

#### `listFilesQuery.ts`

- Paginated file listing
- Tenant-scoped search
- Optional filename filtering
- Total count for pagination

#### `deleteFileCommand.ts`

- Removes from both storage and database
- Graceful handling: DB deletion continues even if storage fails
- Audit trail preserved via updated_at timestamp

### 4. REST API Layer (`src/rest-api/files/`)

HTTP endpoints for file operations:

```
GET    /files                  # List files (query: search, limit, offset)
POST   /files                  # Upload file (multipart/form-data)
GET    /files/:fileId          # Download file (query: download=true)
GET    /files/:fileId/metadata # Get metadata only
DELETE /files/:fileId          # Delete file
```

## Multi-Tenancy

All operations enforce tenant isolation:

- File paths include tenant ID: `{tenantId}/{fileId}/{fileName}`
- Database queries filtered by `tenantId`
- Tenant ID retrieved from session context (`currentTenantId()`)

## Storage Path Strategy

Files are stored with the following structure:

```
uploads/
├── {tenantId1}/
│   ├── {fileId1}/
│   │   └── original-filename.pdf
│   └── {fileId2}/
│       └── document.docx
└── {tenantId2}/
    └── {fileId3}/
        └── image.png
```

Benefits:

- **Isolation**: Each tenant's files separated
- **Collision Prevention**: UUIDs prevent filename collisions
- **Easy Cleanup**: Delete entire tenant directory
- **Scalability**: Easy to distribute across storage backends

## Error Handling

### Common Error Scenarios

| Scenario                | Handling                                     |
| ----------------------- | -------------------------------------------- |
| File not found          | Return 404, check DB and storage consistency |
| Permission denied       | Return 403, verify tenant context            |
| Disk full               | Return 507, alert operations                 |
| Concurrent deletes      | Idempotent, return success on second delete  |
| Corrupt file in storage | Return 500, log for investigation            |

### Rollback Strategies

**Upload failure**:

```
1. Save file to storage ✓
2. Record in DB ✗ → Delete from storage
```

**Delete failure**:

```
1. Delete from storage ✗ → Log warning, continue
2. Delete from DB ✓ → Mark as deleted
```

## Configuration

### Environment Variables

```bash
# Storage configuration
STORAGE_BASE_PATH=./uploads           # Base directory for file storage
STORAGE_MAX_FILE_SIZE=104857600       # 100MB default (optional)
```

### Initialization

```typescript
// In main.ts or initialization code
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";

const storage = new DiskStorage(process.env.STORAGE_BASE_PATH || "./uploads");
```

## Future Enhancements

### S3 Storage Implementation

```typescript
// src/infrastructure/fileStorage/s3Storage.ts
export class S3Storage implements IFileStorage {
  // Implementation using AWS SDK
}
```

### Features to Add

1. **File Versioning**: Track file history
2. **Compression**: Automatic compression for certain types
3. **Scanning**: Virus/malware scanning on upload
4. **Thumbnails**: Generate image thumbnails
5. **Audit Logging**: Comprehensive file operation audit trail
6. **Retention Policies**: Auto-delete files after N days
7. **File Sharing**: Temporary access tokens
8. **Bandwidth Throttling**: Rate limit downloads

## Testing Examples

### Unit Tests

```typescript
// src/application/files/uploadFileCommand.spec.ts
describe("uploadFileCommand", () => {
  it("should upload file and record in database", async () => {
    const buffer = Buffer.from("test content");
    const result = await uploadFileCommand({
      tenantId: "tenant-1",
      fileName: "test.txt",
      mimeType: "text/plain",
      buffer,
    });

    expect(result.id).toBeDefined();
    expect(result.name).toBe("test.txt");
    expect(result.size).toBe(buffer.length);
  });
});
```

### Integration Tests

```typescript
// Upload and download cycle
const uploadResult = await uploadFileCommand({...});
const getResult = await getFileQuery(uploadResult.id, "tenant-1", true);
expect(getResult.content).toEqual(originalBuffer);
```

## Security Considerations

1. **Path Traversal**: Validated in `DiskStorage.getFullPath()`
2. **Tenant Isolation**: All operations scoped by `tenantId`
3. **File Type Validation**: MIME type checked at REST API
4. **Size Limits**: Enforce maximum file size at API layer
5. **Access Control**: Tenant context verified before operations
6. **Concurrent Uploads**: Use optimistic locking in database

## Performance Optimization

1. **Streaming Downloads**: Use Hono streaming for large files
2. **Database Indexes**: Add index on `(tenantId, createdAt)`
3. **Lazy Loading**: Load file content only when requested
4. **Caching**: Cache metadata in Redis for frequently accessed files
5. **Batch Operations**: Parallel uploads using Promise.all()

## API Examples

### Upload File

```bash
curl -X POST \
  -F "file=@document.pdf" \
  http://localhost:3000/files
```

Response:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "document.pdf",
  "mimeType": "application/pdf",
  "size": 2048576,
  "path": "tenant-1/550e8400-e29b-41d4-a716-446655440000/document.pdf",
  "createdAt": "2024-01-15T10:30:00Z",
  "updatedAt": "2024-01-15T10:30:00Z",
  "tenantId": "tenant-1"
}
```

### List Files

```bash
curl "http://localhost:3000/files?search=doc&limit=10&offset=0"
```

Response:

```json
{
  "files": [...],
  "total": 42,
  "limit": 10,
  "offset": 0
}
```

### Download File

```bash
curl "http://localhost:3000/files/550e8400-e29b-41d4-a716-446655440000?download=true" \
  -o document.pdf
```

### Delete File

```bash
curl -X DELETE \
  http://localhost:3000/files/550e8400-e29b-41d4-a716-446655440000
```

## Troubleshooting

### "File not found" errors

Check:

1. File exists in database
2. File exists at storage path
3. Correct tenant context
4. No concurrent deletes

### Storage space issues

Solutions:

1. Increase disk space
2. Implement retention policies
3. Archive old files
4. Switch to S3 or cloud storage

### Performance degradation

Optimize:

1. Add database indexes
2. Implement caching layer
3. Use object storage for large files
4. Consider CDN for frequently downloaded files
