# Storage Configuration Quick Reference

## Disk Storage (Default)

```bash
# .env
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

Setup:

```bash
mkdir -p uploads
chmod 755 uploads
npm run dev
```

## S3 Storage

```bash
# .env
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

Setup:

```bash
npm install @aws-sdk/client-s3
npm run dev
```

## File Path Structure

Both backends use the same file organization:

```
{tenantId}/
  {fileId}/
    original-filename.ext
```

**Local disk**: `./uploads/{tenantId}/{fileId}/{filename}`
**S3**: `s3://bucket/{tenantId}/{fileId}/{filename}`

## Switching Backends

```bash
# From disk to S3
STORAGE_TYPE=s3

# From S3 to disk
STORAGE_TYPE=disk
```

Restart application - no code changes needed!

## Environment Examples

### Local Development

```bash
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

### Staging

```bash
STORAGE_TYPE=s3
S3_BUCKET=proplet-files-staging
AWS_REGION=us-east-1
```

### Production

```bash
STORAGE_TYPE=s3
S3_BUCKET=proplet-files-prod
AWS_REGION=us-east-1
# Use IAM role instead of credentials
```

## Installation

### Disk Storage

No additional packages needed - uses Node.js built-in `fs` module.

### S3 Storage

```bash
npm install @aws-sdk/client-s3
```

This is optional - only install if using S3.

## Troubleshooting

### Disk Storage

```bash
# Check directory exists
ls -la uploads/

# Fix permissions
chmod 755 uploads

# Check available space
df -h ./uploads
```

### S3 Storage

```bash
# Verify credentials
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY

# Check bucket exists
aws s3 ls s3://proplet-files-prod/

# Test upload
curl -X POST -F "file=@test.txt" http://localhost:3000/files
```

## Documentation

| Document                 | Purpose                  |
| ------------------------ | ------------------------ |
| STORAGE_CONFIGURATION.md | Detailed setup guide     |
| S3_SETUP.md              | AWS S3 configuration     |
| FILE_MANAGEMENT.md       | File management overview |
| INTEGRATION_GUIDE.md     | Integration steps        |

## API Usage (Same for Both)

```bash
# Upload
curl -X POST -F "file=@doc.pdf" http://localhost:3000/files

# List
curl http://localhost:3000/files

# Download
curl http://localhost:3000/files/{fileId}?download=true -o doc.pdf

# Delete
curl -X DELETE http://localhost:3000/files/{fileId}
```

## Cost Comparison

| Backend | Setup Time | Monthly Cost |
| ------- | ---------- | ------------ |
| Disk    | 1 min      | Free         |
| S3      | 30 min     | ~$1-10       |

## When to Use

**Use Disk if:**

- Local development
- Testing
- Single server

**Use S3 if:**

- Production
- Multi-server deployment
- Need scalability
- Want auto-backups

## Code - No Changes Needed!

The file management system automatically uses the configured backend. Your application code remains identical:

```typescript
// This works with both disk and S3!
const file = await uploadFileCommand({
  tenantId: "user-123",
  fileName: "document.pdf",
  mimeType: "application/pdf",
  buffer: fileBuffer,
});
```

The backend switching happens automatically through environment configuration.
