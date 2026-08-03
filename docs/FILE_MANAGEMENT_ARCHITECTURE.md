# File Management System Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT APPLICATION                        │
│                      (Mobile App / Web UI)                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    HTTP REST API Calls
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    REST API LAYER                                 │
│                  src/rest-api/files/                              │
├─────────────────────────────────────────────────────────────────┤
│  GET  /files              → List files                           │
│  POST /files              → Upload file                          │
│  GET  /files/:id          → Download file                        │
│  GET  /files/:id/metadata → Get metadata                         │
│  DELETE /files/:id        → Delete file                          │
│  POST /files/:id/share    → Generate share link (advanced)       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    Hono Request Handling
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                APPLICATION LAYER (CQRS Pattern)                  │
│                 src/application/files/                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Commands (State Change):                                        │
│  ├─ uploadFileCommand       → Save + DB Record                   │
│  ├─ deleteFileCommand       → Remove from DB + Storage           │
│  └─ batchUploadCommand      → Multiple uploads                   │
│                                                                   │
│  Queries (Read-Only):                                            │
│  ├─ getFileQuery            → Retrieve file ± content            │
│  ├─ listFilesQuery          → Paginated list + search            │
│  └─ getFileCategoryQuery    → Files by category                  │
│                                                                   │
└────────────────────────────┬────────────────────────────────────┘
                    ▼            ▼
        ┌──────────────────┬──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│  STORAGE LAYER   │ │ DATABASE LAYER   │ │  VALIDATION      │
│  (Abstraction)   │ │                  │ │  LAYER           │
├──────────────────┤ ├──────────────────┤ ├──────────────────┤
│ IFileStorage     │ │  dbContext       │ │ File validators  │
│ (Interface)      │ │  (Drizzle ORM)   │ │ MIME type check  │
└────────┬─────────┘ └────────┬─────────┘ │ Size limits      │
         │                    │           │ Checksums       │
         │                    │           └──────────────────┘
    ┌────┴────┐         ┌─────┴─────┐
    │          │         │           │
    ▼          ▼         ▼           ▼
┌─────────┐ ┌─────┐ ┌──────────┐ ┌─────────────┐
│ Disk    │ │ S3  │ │PostgreSQL│ │File Metadata│
│Storage  │ │(TBD)│ │Database  │ │Table        │
└─────────┘ └─────┘ └──────────┘ └─────────────┘
```

## Data Flow Diagrams

### Upload Flow

```
Client File
    │
    ▼
HTTP POST /files (multipart/form-data)
    │
    ▼
REST API Validation
├─ File size check
├─ MIME type validation
└─ Tenant context verification
    │
    ▼
uploadFileCommand
    │
    ├─ Generate unique ID (UUID)
    ├─ Calculate storage path: {tenantId}/{fileId}/{filename}
    │
    ├─► fileStorage.saveFile(path, buffer)
    │   │
    │   └─► Create directories if needed
    │       Write file to disk
    │
    ├─► Database: INSERT into files table
    │   ├─ id
    │   ├─ name
    │   ├─ mimeType
    │   ├─ size
    │   ├─ path
    │   └─ tenantId
    │
    ├─ On DB error: Rollback (delete from storage)
    │
    ▼
HTTP 201 Created
{
  id: "uuid",
  name: "document.pdf",
  path: "tenant-1/uuid/document.pdf",
  ...
}
```

### Download Flow

```
Client Request
    │
    ▼
HTTP GET /files/{fileId}?download=true
    │
    ▼
REST API
├─ Extract fileId from URL
├─ Get tenantId from session
└─ Check authorization
    │
    ▼
getFileQuery(fileId, tenantId, includeContent=true)
    │
    ├─► Database: SELECT FROM files
    │   WHERE id = ? AND tenantId = ?
    │
    └─► fileStorage.readFile(storagePath)
        │
        └─► fs.readFile() ─► Buffer
    │
    ▼
REST API Response
├─ Set Content-Type header
├─ Set Content-Disposition (attachment)
└─ Stream file content
    │
    ▼
Client File
```

### Delete Flow

```
Client Request
    │
    ▼
HTTP DELETE /files/{fileId}
    │
    ▼
REST API Validation
├─ Extract fileId
├─ Get tenantId from session
└─ Verify authorization
    │
    ▼
deleteFileCommand(fileId, tenantId)
    │
    ├─► Database: SELECT FROM files
    │   WHERE id = ? AND tenantId = ?
    │
    ├─ Get storagePath from result
    │
    ├─► fileStorage.deleteFile(storagePath)
    │   Try: fs.unlink(file)
    │   Catch: Log warning, continue
    │
    ├─► Database: DELETE FROM files
    │   WHERE id = ? AND tenantId = ?
    │
    ▼
HTTP 200 OK
{ success: true }
```

## Multi-Tenant Isolation

```
┌─────────────────────────────────────────────────────┐
│            Shared File Management System             │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Session Context: currentTenantId()                 │
│      └─► Extract from Hono context                 │
│          Validated per request                     │
│                                                     │
│  Storage Layer Isolation:                          │
│  uploads/                                          │
│    ├── tenant-uuid-1/                              │
│    │   ├── file-uuid-1/document.pdf                │
│    │   ├── file-uuid-2/image.png                   │
│    │   └── file-uuid-3/spreadsheet.xlsx            │
│    │                                                │
│    ├── tenant-uuid-2/                              │
│    │   ├── file-uuid-4/contract.pdf                │
│    │   └── file-uuid-5/receipt.jpg                 │
│    │                                                │
│    └── tenant-uuid-3/                              │
│        └── file-uuid-6/report.docx                 │
│                                                     │
│  Database Layer Isolation:                         │
│  ├─ WHERE tenantId = ?                             │
│  ├─ All queries scoped by tenant                   │
│  ├─ Indexes on (tenantId, fileId)                  │
│  └─ Foreign key to tenants table                   │
│                                                     │
│  API Layer Isolation:                              │
│  ├─ No cross-tenant file access                    │
│  ├─ Tenant verified before operations              │
│  └─ Audit logging includes tenantId                │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Error Handling Strategy

```
                    File Operation
                          │
                    ┌─────┴─────┐
                    │           │
                    ▼           ▼
              Success       Error
                │            ├─► Validation Error (400)
                │            │   ├─ Invalid file size
                │            │   ├─ Wrong MIME type
                │            │   └─ Missing required fields
                │            │
                │            ├─► Permission Error (403)
                │            │   ├─ Wrong tenant
                │            │   └─ Insufficient access
                │            │
                │            ├─► Not Found Error (404)
                │            │   ├─ File not in DB
                │            │   ├─ File not in storage
                │            │   └─ Database record missing
                │            │
                │            ├─► Conflict Error (409)
                │            │   ├─ File already exists
                │            │   └─ Concurrent modification
                │            │
                │            └─► Server Error (500)
                │                ├─ Disk write failure
                │                ├─ DB transaction failure
                │                ├─ Corrupt file detected
                │                └─ Storage backend unreachable
                │
                ▼
            Return Result
            ├─ File metadata
            ├─ File content (optional)
            ├─ Success/error status
            └─ HTTP status code
```

## Storage Path Structure

```
Base Directory: ./uploads/

Structure:
  uploads/
  │
  ├─ {tenantId}                 ← Tenant isolation
  │  │
  │  ├─ {fileId}                ← UUID collision prevention
  │  │  │
  │  │  ├─ original-filename.pdf ← Preserves original name
  │  │  │
  │  │  └─ [thumbnail.jpg]       ← Generated artifacts
  │  │
  │  └─ {fileId}/
  │     └─ another-file.docx
  │
  └─ {tenantId}/
     └─ {fileId}/
        └─ ...

Benefits:
  ✓ Hierarchical organization
  ✓ Easy bulk operations (delete tenant)
  ✓ Minimal collisions (UUID + tenant)
  ✓ Scalable (easy to distribute)
  ✓ Clear audit trail
  ✓ Migration-friendly
```

## Technology Stack

```
┌──────────────────────────────────────────┐
│   Framework & Web Server                  │
│   ├─ Hono (Lightweight framework)         │
│   └─ Node.js HTTP Server                  │
├──────────────────────────────────────────┤
│   Data Layer                               │
│   ├─ Drizzle ORM (Type-safe DB access)    │
│   ├─ PostgreSQL (Database)                │
│   └─ Node.js fs (File I/O)                │
├──────────────────────────────────────────┤
│   Type Safety & Validation                │
│   └─ Zod (Runtime validation)             │
├──────────────────────────────────────────┤
│   Storage Backends                        │
│   ├─ Local Disk (Implemented)             │
│   ├─ AWS S3 (To implement)                │
│   └─ Azure Blob (To implement)            │
├──────────────────────────────────────────┤
│   Testing                                  │
│   └─ Node.js built-in test runner         │
└──────────────────────────────────────────┘
```

## Scaling Considerations

```
       Local Development
              │
              ▼
    Single Server (Disk Storage)
         │
         ├─ Monolithic deployment
         ├─ All traffic to one server
         └─ Shared local filesystem

              │
              ▼
       Production (Small Scale)
         │
         ├─ Multiple app servers
         ├─ Shared NFS storage
         └─ Load balanced

              │
              ▼
    Production (Large Scale)
         │
         ├─ Distributed app servers
         ├─ S3 / Cloud storage
         ├─ Database replication
         ├─ CDN for downloads
         └─ Background job queue
```

## Key Design Patterns

```
Pattern                Implementation
─────────────────────────────────────
Clean Architecture    Layered (API → App → Infra)
Repository Pattern    dbContext abstracts DB
Strategy Pattern      IFileStorage interface
CQRS                  Commands + Queries
Singleton             fileStorage instance
Factory               createFileStorage()
Observer              Event-driven processing
Atomic Operations     Transaction-like behavior
Graceful Degradation  Storage failure handling
```

## Database Schema

```
┌─────────────────────────────────────┐
│           files table                 │
├─────────────────────────────────────┤
│ id (UUID, PK)                       │ ──┐
│ name (text)                         │   │
│ mimeType (text)                     │   │ File Metadata
│ size (integer)                      │   │
│ path (text)                         │   │
│ createdAt (timestamp)               │   │
│ updatedAt (timestamp)               │ ──┘
│ tenantId (UUID, FK → tenants)       │
└─────────────────────────────────────┘
        │
        │ Foreign Key
        │
        ▼
┌─────────────────────────────────────┐
│         tenants table                 │
├─────────────────────────────────────┤
│ id (UUID, PK)                       │
│ name (text)                         │
│ ...                                 │
└─────────────────────────────────────┘

Optional Tables:
─────────────────────────────────────
┌─────────────────────┬──────────────┐
│ fileCategories      │ fileMetadata │
├─────────────────────┼──────────────┤
│ id (UUID, PK)       │ id (UUID)    │
│ fileId (FK)         │ fileId (FK)  │
│ category (text)     │ key (text)   │
│ createdAt           │ value (text) │
└─────────────────────┴──────────────┘

┌──────────────────────┐
│   fileAuditLog       │
├──────────────────────┤
│ id (UUID, PK)        │
│ fileId (FK)          │
│ tenantId (FK)        │
│ action (text)        │
│ userId (FK, opt)     │
│ details (jsonb)      │
│ createdAt            │
└──────────────────────┘
```

## Deployment Checklist

```
Pre-Deployment:
☐ Run tests: npm test
☐ Build: npm run build
☐ Lint: npm run lint

Database:
☐ Generate migration: drizzle-kit generate:pg
☐ Apply migration: drizzle-kit migrate:pg
☐ Create indexes
☐ Verify schema

Storage:
☐ Create uploads directory
☐ Set correct permissions (755)
☐ Verify disk space
☐ Configure backup

Application:
☐ Set environment variables
☐ Configure storage path
☐ Initialize file storage
☐ Health check endpoints

Monitoring:
☐ Enable request logging
☐ Set up error alerts
☐ Monitor disk usage
☐ Track file operations
```
