# AWS S3 Storage Setup Guide

This guide explains how to configure and use AWS S3 as your file storage backend instead of local disk storage.

## Overview

The file management system supports both local disk storage (default) and AWS S3. You can easily switch between them using environment variables.

## Prerequisites

### AWS Account Setup

1. **Create an AWS Account** at https://aws.amazon.com
2. **Create an S3 Bucket** for your application files
3. **Create an IAM User** with S3 permissions
4. **Get Access Keys** for the IAM user

### Step 1: Create S3 Bucket

1. Go to AWS S3 Console: https://s3.console.aws.amazon.com
2. Click "Create bucket"
3. Enter bucket name (e.g., `proplet-files-prod`)
4. Choose region (e.g., `us-east-1`)
5. Click "Create bucket"

### Step 2: Create IAM User with S3 Access

1. Go to IAM Console: https://console.aws.amazon.com/iam
2. Click "Users" → "Create user"
3. Enter username (e.g., `proplet-app`)
4. Click "Next"
5. Click "Attach policies directly"
6. Search and select `AmazonS3FullAccess` (or create custom policy)
7. Click "Next" → "Create user"

### Step 3: Generate Access Keys

1. Click on the created user
2. Go to "Security credentials" tab
3. Click "Create access key"
4. Choose "Application running outside AWS"
5. Click "Next"
6. Copy the access key ID and secret access key
7. **Save these securely** - you won't see them again

## Installation

### Install AWS SDK

```bash
npm install @aws-sdk/client-s3
```

## Configuration

### Environment Variables

Create or update your `.env` file:

```bash
# Use S3 storage
STORAGE_TYPE=s3

# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
S3_BUCKET=proplet-files-prod
```

### Configuration by Environment

**Development (Local Disk):**

```bash
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

**Staging (S3):**

```bash
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-staging
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

**Production (S3):**

```bash
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

## Usage

The API usage remains exactly the same - no code changes needed!

### Upload File

```bash
curl -X POST \
  -F "file=@document.pdf" \
  http://localhost:3000/files
```

### Download File

```bash
curl "http://localhost:3000/files/{fileId}?download=true" -o document.pdf
```

### List Files

```bash
curl "http://localhost:3000/files?search=doc&limit=10"
```

### Delete File

```bash
curl -X DELETE http://localhost:3000/files/{fileId}
```

## S3 File Organization

Files in your S3 bucket are organized as:

```
s3://proplet-files-prod/
  {tenantId}/
    {fileId}/
      original-filename.pdf
```

This maintains the same hierarchy and multi-tenant isolation as disk storage.

## Security Considerations

### 1. IAM Policy Restriction

Create a custom policy limiting access to your bucket only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::proplet-files-prod", "arn:aws:s3:::proplet-files-prod/*"]
    }
  ]
}
```

### 2. Bucket Policy

Restrict public access:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlockPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::proplet-files-prod", "arn:aws:s3:::proplet-files-prod/*"],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### 3. Environment Variable Security

**Never commit access keys to git!**

Use a secret management system:

- **Development**: Local `.env` file (add to `.gitignore`)
- **Staging**: AWS Secrets Manager or environment variables
- **Production**: AWS IAM roles or Secrets Manager

### 4. Enable Versioning (Optional)

Enable S3 versioning for file recovery:

1. Go to S3 Console
2. Select bucket
3. Click "Properties"
4. Scroll to "Versioning"
5. Click "Enable"

## Performance Optimization

### 1. Use CloudFront (CDN)

For faster downloads, use AWS CloudFront:

```bash
# Update download endpoint to use CloudFront
GET https://d123abc.cloudfront.net/files/{fileId}
```

### 2. Enable S3 Transfer Acceleration

For faster uploads from distributed locations:

1. Go to S3 Console → Bucket
2. Click "Properties"
3. Find "Transfer acceleration"
4. Click "Enable"

### 3. Multipart Upload

For large files, the S3SDK automatically uses multipart upload.

## Monitoring and Logging

### Enable S3 Access Logging

1. Go to S3 Console → Bucket → Properties
2. Find "Server access logging"
3. Click "Edit"
4. Create a target bucket for logs
5. Enable logging

### CloudWatch Metrics

Monitor S3 performance:

1. Go to CloudWatch Console
2. Click "Dashboards"
3. Create dashboard
4. Add S3 metrics:
   - BucketSizeBytes
   - NumberOfObjects
   - 4xxErrors
   - 5xxErrors

### Cost Monitoring

```bash
# Set up billing alerts
# Go to Billing Dashboard → Budget
# Create budget for S3 costs
```

## Cost Estimation

S3 pricing includes:

| Item     | Cost                                   |
| -------- | -------------------------------------- |
| Storage  | $0.023 per GB/month (us-east-1)        |
| Upload   | Free                                   |
| Download | $0.09 per GB                           |
| Requests | $0.0004 per 1,000 PUT/COPY/POST/DELETE |
| Requests | $0.0002 per 1,000 GET/HEAD             |

**Example:** 1GB of files with 1000 downloads/month

```
Storage:    1 GB × $0.023 = $0.023
Downloads:  1 GB × $0.09  = $0.09
Requests:   $0.02 (approximately)
Total:      ~$0.13/month
```

## Troubleshooting

### "Access Denied" Error

```
Error: User: arn:aws:iam::123456789:user/proplet-app
is not authorized to perform: s3:PutObject
```

**Solution:**

- Verify IAM policy includes S3 permissions
- Check access key is correct
- Verify bucket name is correct

### "NoSuchBucket" Error

```
Error: The specified bucket does not exist
```

**Solution:**

- Check bucket name spelling
- Verify bucket exists in the specified region
- Check AWS_REGION matches bucket region

### "SlowDown" Error

```
Error: Please reduce your request rate
```

**Solution:**

- Add exponential backoff retry logic
- Reduce request rate
- Enable S3 Transfer Acceleration
- Use multipart upload for large files

### Connection Timeout

```
Error: RequestTimeout: Request did not complete within 30000 ms
```

**Solution:**

- Check internet connection
- Verify AWS credentials
- Check S3 bucket permissions
- Increase timeout in SDK configuration

## Switching Between Storage Backends

### Switch from Disk to S3

1. Update `.env`:

```bash
STORAGE_TYPE=s3
S3_BUCKET=proplet-files-prod
# ... other S3 config
```

2. Restart application

3. Old files on disk remain unchanged (you can keep as backup)

4. New files go to S3

### Migrate Existing Files to S3

```typescript
// Migration script example
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";
import { S3Storage } from "#infrastructure/fileStorage/s3Storage";
import fs from "fs";
import path from "path";

async function migrateToS3() {
  const diskStorage = new DiskStorage("./uploads");
  const s3Storage = new S3Storage("proplet-files-prod");

  // Recursively copy all files
  const files = await diskStorage.listFiles(".");

  for (const file of files) {
    const content = await diskStorage.readFile(file);
    await s3Storage.saveFile(file, content);
    console.log(`Migrated: ${file}`);
  }

  console.log("Migration complete!");
}

migrateToS3().catch(console.error);
```

## Advanced Configuration

### Custom Region Selection

Some regions have different pricing:

| Region         | Use Case              |
| -------------- | --------------------- |
| us-east-1      | Lowest cost, US users |
| eu-west-1      | European users, GDPR  |
| ap-southeast-1 | Asia-Pacific users    |
| ca-central-1   | Canada                |

```bash
AWS_REGION=eu-west-1  # For European deployment
```

### S3 Intelligent-Tiering (Optional)

Automatically move files to cheaper storage classes:

1. Go to S3 Console → Bucket
2. Click "Management"
3. Click "Create lifecycle configuration"
4. Add rules to transition files after 30+ days

## Rollback to Disk Storage

If you need to switch back to disk storage:

1. Update `.env`:

```bash
STORAGE_TYPE=disk
STORAGE_BASE_PATH=./uploads
```

2. Restart application

3. Download files from S3 as backup (optional)

## Support

For AWS S3 issues:

- AWS Documentation: https://docs.aws.amazon.com/s3/
- AWS SDK for JavaScript: https://docs.aws.amazon.com/AWSJavaScriptSDK/latest/
- AWS Support: https://console.aws.amazon.com/support/

For Proplet file management issues:

- See: `docs/FILE_MANAGEMENT.md`
- See: `docs/FILE_MANAGEMENT_ADVANCED.md`
