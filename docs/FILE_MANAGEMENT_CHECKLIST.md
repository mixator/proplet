# File Management Implementation Checklist

Use this checklist to implement and verify the file management system.

## Phase 1: Core Setup ✓

- [x] Create domain entity (`core/entities/file.ts`)
- [x] Create database schema (`infrastructure/schema/files.ts`)
- [x] Create storage interface (`infrastructure/fileStorage/storage.ts`)
- [x] Implement disk storage (`infrastructure/fileStorage/diskStorage.ts`)

## Phase 2: Application Layer ✓

- [x] Create upload command (`application/files/uploadFileCommand.ts`)
- [x] Create read query (`application/files/getFileQuery.ts`)
- [x] Create list query (`application/files/listFilesQuery.ts`)
- [x] Create delete command (`application/files/deleteFileCommand.ts`)

## Phase 3: API Layer ✓

- [x] Create REST endpoints (`rest-api/files/index.ts`)
- [ ] Add input validation with Zod
- [ ] Add file size limits
- [ ] Add MIME type restrictions

## Phase 4: Database Integration

- [ ] Update `infrastructure/schema/index.ts` to export files table
- [ ] Update `infrastructure/dbContext.ts` to include files relations
- [ ] Create and run Drizzle migration:
  ```bash
  drizzle-kit generate:pg
  drizzle-kit migrate:pg
  ```

## Phase 5: Main App Integration

- [ ] Import files API in `src/main.ts`
- [ ] Register route: `app.route("/files", filesApi)`
- [ ] Test with curl or Postman

## Phase 6: Testing

### Unit Tests

- [ ] `uploadFileCommand.spec.ts`
  - [ ] Valid file upload
  - [ ] Storage failure rollback
  - [ ] DB failure cleanup

- [ ] `getFileQuery.spec.ts`
  - [ ] File found scenario
  - [ ] File not found scenario
  - [ ] Tenant isolation

- [ ] `deleteFileCommand.spec.ts`
  - [ ] Successful deletion
  - [ ] Storage failure handling
  - [ ] Tenant isolation

- [ ] `diskStorage.ts` tests
  - [ ] Directory traversal prevention
  - [ ] File CRUD operations
  - [ ] Metadata retrieval
  - [ ] Pattern matching

### Integration Tests

- [ ] Upload → Download cycle
- [ ] Upload → List → Delete
- [ ] Concurrent uploads
- [ ] Large file handling
- [ ] Tenant isolation
- [ ] Error scenarios

### API Tests (Manual or Postman)

- [ ] POST /files - Upload
- [ ] GET /files - List
- [ ] GET /files/:id - Download
- [ ] GET /files/:id/metadata - Metadata only
- [ ] DELETE /files/:id - Delete
- [ ] Error responses (404, 400, 500)

## Phase 7: Production Readiness

### Security

- [ ] File type whitelist configured
- [ ] Max file size enforced
- [ ] Virus scanning integrated (optional)
- [ ] Access logs enabled
- [ ] Tenant isolation verified

### Performance

- [ ] Database indexes created
- [ ] Streaming configured for large files
- [ ] Caching strategy implemented (optional)
- [ ] Load tested with realistic file sizes

### Operations

- [ ] Backup strategy documented
- [ ] Retention policy defined
- [ ] Storage monitoring set up
- [ ] Error alerting configured
- [ ] Logging includes file operation context

## Phase 8: Documentation

- [x] FILE_MANAGEMENT.md - Complete guide
- [ ] API documentation generated
- [ ] Deployment guide for storage
- [ ] Operations runbook
- [ ] Troubleshooting guide

## Phase 9: Future Enhancements (Optional)

- [ ] S3 storage backend implementation
- [ ] File versioning system
- [ ] Image thumbnail generation
- [ ] Automatic file compression
- [ ] Temporary share links
- [ ] Audit logging
- [ ] File retention policies
- [ ] CDN integration

## Known Issues & Gotchas

- [ ] `listFilesQuery` may need adjustment based on actual `dbContext` API
- [ ] `getFileQuery` imports `files` schema dynamically - verify table relations
- [ ] Ensure `currentTenantId()` is properly initialized in session context
- [ ] File paths use forward slashes internally for consistency

## Quick Start (After Phases 1-3)

```bash
# 1. Install dependencies (if needed)
npm install

# 2. Run database migration
npm run db:migrate

# 3. Start server
npm run dev

# 4. Test upload
curl -X POST \
  -F "file=@myfile.txt" \
  http://localhost:3000/files

# 5. List files
curl http://localhost:3000/files

# 6. Download file
curl http://localhost:3000/files/{fileId}?download=true -o output.txt

# 7. Delete file
curl -X DELETE http://localhost:3000/files/{fileId}
```

## Testing File Upload/Download

### Using curl

```bash
# Upload
curl -X POST -F "file=@test.pdf" http://localhost:3000/files

# Download
curl http://localhost:3000/files/{id}?download=true > test.pdf

# Get metadata only
curl http://localhost:3000/files/{id}/metadata
```

### Using Postman

1. Create POST request to `http://localhost:3000/files`
2. In Body, select "form-data"
3. Add "file" field of type "File"
4. Select your file
5. Send

## Integration Points Needed

- [ ] Update `src/main.ts` to mount files router
- [ ] Update `infrastructure/schema/index.ts` to export files
- [ ] Create Drizzle migration for files table
- [ ] Configure storage base path (env var or config)
- [ ] Add types/relations to `dbContext.ts`

## Notes

- All operations are tenant-scoped using `currentTenantId()`
- Files are stored at: `uploads/{tenantId}/{fileId}/{originalName}`
- Database stores metadata + storage path for retrieval
- Storage interface allows easy swapping of backends
- Error handling includes automatic rollback on failures
