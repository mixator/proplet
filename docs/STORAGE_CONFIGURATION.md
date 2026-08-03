# Storage Configuration Guide

This guide explains how to configure and switch between Disk and S3 storage backends.

## Storage Architecture

```
IFileStorage (Interface)
  ├── DiskStorage (Local filesystem)
  └── S3Storage (AWS S3)
```

The file management system uses a **Strategy Pattern** with automatic backend selection based on environment variables.

## Quick Comparison

| Feature         | Disk            | S3                              |
| --------------- | --------------- | ------------------------------- |
| Setup Time      | Minutes         | ~30 minutes                     |
| Cost            | Free            | $0.023/GB/month + data transfer |
| Scalability     | Limited by disk | Unlimited                       |
| Multi-region    | No              | Yes                             |
| Availability    | Local server    | 99.99% SLA                      |
| CDN Integration | Manual          | CloudFront native               |
| Backup/Recovery | Manual          | Automatic versioning            |
| Best For        | Development     | Production                      |

## Configuration

### Environment Variables

```bash
# Storage selection
STORAGE_TYPE=disk        # "disk" (default) or "s3"

# Disk storage options
STORAGE_BASE_PATH=./uploads

# S3 options
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=xxx
AWS_SECRET_ACCESS_KEY=xxx
S3_BUCKET=my-bucket
```

### Development Setup (Disk Storage)

```bash
# .env.local or .env.development
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

Create the uploads directory:

```bash
mkdir -p uploads
chmod 755 uploads
```

### Production Setup (S3 Storage)

```bash
# .env.production
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

## Disk Storage

### Setup

```bash
# Create uploads directory
mkdir -p uploads
chmod 755 uploads

# Set environment
export STORAGE_TYPE=disk
export STORAGE_BASE_PATH=./uploads
```

### Configuration

```typescript
// .env
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

### Directory Structure

```
project/
├── uploads/
│   ├── {tenantId1}/
│   │   ├── {fileId1}/
│   │   │   └── document.pdf
│   │   └── {fileId2}/
│   │       └── image.png
│   └── {tenantId2}/
│       └── {fileId3}/
│           └── report.docx
├── src/
├── package.json
└── .env
```

### Pros

✅ Zero setup time
✅ No cost
✅ Great for development/testing
✅ Easy local debugging
✅ Fast access

### Cons

❌ Limited by disk space
❌ Single point of failure
❌ No redundancy
❌ Manual backups needed
❌ Not scalable

### Best Practices

1. **Backup regularly**: Copy `uploads/` directory
2. **Monitor disk space**: Set up alerts
3. **Organize by tenant**: Automatic via system
4. **Regular cleanup**: Remove old test files

## S3 Storage

### Prerequisites

1. AWS Account
2. S3 Bucket created
3. IAM User with S3 access
4. Access keys generated

See [S3_SETUP.md](./S3_SETUP.md) for detailed instructions.

### Installation

```bash
npm install @aws-sdk/client-s3
```

### Configuration

```bash
# .env
STORAGE_TYPE=s3
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
S3_BUCKET=proplet-files-prod
```

### S3 Bucket Structure

```
s3://proplet-files-prod/
├── {tenantId1}/
│   ├── {fileId1}/
│   │   └── document.pdf
│   └── {fileId2}/
│       └── image.png
└── {tenantId2}/
    └── {fileId3}/
        └── report.docx
```

### Pros

✅ Unlimited scalability
✅ 99.99% availability
✅ Automatic redundancy
✅ Built-in versioning
✅ CDN integration (CloudFront)
✅ Managed backups
✅ Multi-region support

### Cons

❌ Requires AWS account
❌ Costs money
❌ More complex setup
❌ Network latency
❌ IAM policy management

### Best Practices

1. **Use IAM Roles**: Never store AWS keys in code
2. **Enable Versioning**: For file recovery
3. **Set Lifecycle Rules**: Archive old files
4. **Enable Access Logging**: For audit trail
5. **Use CloudFront**: For faster downloads
6. **Monitor Costs**: Set up billing alerts

## Switching Storage Backends

### From Disk to S3 (for production deployment)

1. **Install AWS SDK**:

   ```bash
   npm install @aws-sdk/client-s3
   ```

2. **Create S3 bucket** and get credentials

3. **Update .env**:

   ```bash
   STORAGE_TYPE=s3
   AWS_REGION=us-east-1
   S3_BUCKET=proplet-files-prod
   AWS_ACCESS_KEY_ID=...
   AWS_SECRET_ACCESS_KEY=...
   ```

4. **Restart application**:

   ```bash
   npm run dev
   ```

5. **Verify it works**:
   ```bash
   curl -X POST -F "file=@test.txt" http://localhost:3000/files
   ```

### From S3 to Disk (for testing)

1. **Update .env**:

   ```bash
   STORAGE_TYPE=disk
   STORAGE_BASE_PATH=./uploads
   ```

2. **Restart application**

3. **Existing S3 files remain** (optional backup)

## File Migration

### Migrate from Disk to S3

```typescript
// scripts/migrate-to-s3.ts
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";
import { S3Storage } from "#infrastructure/fileStorage/s3Storage";
import fs from "fs";

async function migrate() {
  const disk = new DiskStorage("./uploads");
  const s3 = new S3Storage("proplet-files-prod");

  console.log("Starting migration...");

  const files = await disk.listFiles(".");

  for (const file of files) {
    const content = await disk.readFile(file);
    await s3.saveFile(file, content);
    console.log(`✓ Migrated: ${file}`);
  }

  console.log("✓ Migration complete!");
}

migrate().catch(console.error);
```

Run:

```bash
npx ts-node scripts/migrate-to-s3.ts
```

### Backup from S3 to Disk

```typescript
// scripts/backup-s3-to-disk.ts
import { S3Storage } from "#infrastructure/fileStorage/s3Storage";
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";

async function backup() {
  const s3 = new S3Storage("proplet-files-prod");
  const disk = new DiskStorage("./backups");

  console.log("Starting backup...");

  const files = await s3.listFiles(".");

  for (const file of files) {
    const content = await s3.readFile(file);
    await disk.saveFile(file, content);
    console.log(`✓ Backed up: ${file}`);
  }

  console.log("✓ Backup complete!");
}

backup().catch(console.error);
```

## Environment-Specific Configuration

### Development

```bash
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

### Staging

```bash
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-staging
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

### Production

```bash
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
# Use IAM role instead of keys (AWS Lambda/ECS)
# Or use Secrets Manager
```

## Monitoring and Logging

### Disk Storage Monitoring

```bash
# Monitor disk usage
df -h ./uploads

# List all files
find uploads/ -type f | wc -l

# Check file sizes
du -sh uploads/
```

### S3 Monitoring

```bash
# List objects in bucket (AWS CLI)
aws s3 ls s3://proplet-files-prod/ --recursive --summarize

# Get bucket size
aws s3api list-objects-v2 \
  --bucket proplet-files-prod \
  --query '[Contents[].Size] | add'

# Monitor costs
# AWS Console → Billing → Bills
```

## Troubleshooting

### Disk Storage Issues

| Problem             | Solution                            |
| ------------------- | ----------------------------------- |
| "Permission denied" | `chmod 755 uploads`                 |
| "Disk full"         | Clean up old files or increase disk |
| Files not found     | Check path in database              |

### S3 Storage Issues

| Problem         | Solution                           |
| --------------- | ---------------------------------- |
| "Access Denied" | Check IAM policy                   |
| "NoSuchBucket"  | Verify bucket name                 |
| Slow uploads    | Check network, enable acceleration |
| Slow downloads  | Use CloudFront CDN                 |

See [S3_SETUP.md](./S3_SETUP.md) for more S3 troubleshooting.

## Performance Comparison

### Disk Storage

- **Upload**: ~50MB/s (SSD dependent)
- **Download**: ~50MB/s (network dependent)
- **List**: ~1000 files/s

### S3 Storage

- **Upload**: ~10MB/s (with SDK overhead)
- **Download**: ~10MB/s (network dependent)
- **List**: ~1000 objects/s

Note: S3 performance can be improved with:

- Transfer Acceleration
- CloudFront caching
- Multipart upload
- Connection pooling

## Cost Breakdown (S3)

**Assumptions**: 10GB stored, 1000 downloads/month

```
Storage:      10 GB × $0.023/GB         = $0.23
Downloads:    10 GB × $0.09/GB          = $0.90
PUT Requests: 100 × $0.000004           = $0.0004
GET Requests: 1000 × $0.000002          = $0.002
────────────────────────────────────────
Total:                                    ~$1.13/month
```

## Choosing Your Storage

### Use Disk if:

- Developing locally
- Testing the system
- Single server deployment
- High-frequency access

### Use S3 if:

- Production environment
- Distributed/multi-server setup
- Need scalability
- Want automatic backups
- Require CDN integration
- Multi-region support

## See Also

- [S3_SETUP.md](./S3_SETUP.md) - Detailed S3 configuration
- [FILE_MANAGEMENT.md](./FILE_MANAGEMENT.md) - File management overview
- [FILE_MANAGEMENT_ADVANCED.md](./FILE_MANAGEMENT_ADVANCED.md) - Advanced patterns
