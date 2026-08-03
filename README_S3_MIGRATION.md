# S3 Migration Guide

Complete guide for migrating from local disk storage to AWS S3.

## Why Migrate to S3?

| Factor           | Disk     | S3           |
| ---------------- | -------- | ------------ |
| **Cost**         | Free     | ~$1-15/month |
| **Scalability**  | Limited  | Unlimited    |
| **Availability** | 99%      | 99.99%       |
| **Backups**      | Manual   | Automatic    |
| **Multi-region** | No       | Yes          |
| **Best For**     | Dev/Test | Production   |

## Prerequisites

- AWS Account (create at https://aws.amazon.com)
- S3 bucket created
- IAM user with S3 access
- Node.js application running

## 3-Step Migration

### Step 1: AWS Setup (15 minutes)

Follow [docs/S3_SETUP.md](./docs/S3_SETUP.md) to:

1. Create S3 bucket
2. Create IAM user
3. Generate access keys
4. Set up security policies

### Step 2: Update Application (5 minutes)

```bash
# Install AWS SDK
npm install @aws-sdk/client-s3

# Update .env
cat > .env << 'EOF'
STORAGE_TYPE=s3
AWS_REGION=us-east-1
S3_BUCKET=proplet-files-prod
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
EOF
```

### Step 3: Verify & Deploy (5 minutes)

```bash
# Restart application
npm run dev

# Test upload
curl -X POST -F "file=@test.txt" http://localhost:3000/files

# Check S3 bucket
aws s3 ls s3://proplet-files-prod/ --recursive
```

## Before Migration Checklist

- [ ] AWS account created
- [ ] S3 bucket created in desired region
- [ ] IAM user with S3 permissions created
- [ ] Access keys generated and saved
- [ ] Application deployed successfully
- [ ] Disk storage working properly
- [ ] Database backups created

## Migration Process

### Option A: Direct Switch (For Small Deployments)

Best for: <100GB files, acceptable downtime

```bash
# 1. Create S3 bucket
# 2. Create IAM user
# 3. Install SDK: npm install @aws-sdk/client-s3
# 4. Update .env with S3 config
# 5. Restart: npm run dev
# 6. Done! New files go to S3
```

**Pros:**

- Quick (15 minutes)
- Simple
- No downtime needed

**Cons:**

- Old files stay on disk
- Need to manage both locations

### Option B: Gradual Migration (For Large Deployments)

Best for: >100GB files, zero downtime required

```bash
# 1. Deploy S3 adapter (no .env change yet)
# 2. Run in parallel mode for testing
# 3. Migrate old files to S3
# 4. Switch STORAGE_TYPE=s3
# 5. Verify all files accessible
# 6. Delete disk files (optional)
```

**Migration Script:**

```typescript
// scripts/migrate-to-s3.ts
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";
import { S3Storage } from "#infrastructure/fileStorage/s3Storage";

async function migrate() {
  const disk = new DiskStorage("./uploads");
  const s3 = new S3Storage("proplet-files-prod");

  console.log("Starting migration...");

  const files = await disk.listFiles(".");

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const content = await disk.readFile(file);
    await s3.saveFile(file, content);
    console.log(`[${i + 1}/${files.length}] ${file}`);
  }

  console.log("✓ Migration complete!");
}

migrate().catch((err) => {
  console.error("Migration failed:", err);
  process.exit(1);
});
```

Run:

```bash
npm run ts-node scripts/migrate-to-s3.ts
```

### Option C: Dual-Write (For Zero-Downtime Migration)

Best for: Critical production systems, maximum safety

```typescript
// Store in both disk and S3 temporarily
import { DiskStorage } from "#infrastructure/fileStorage/diskStorage";
import { S3Storage } from "#infrastructure/fileStorage/s3Storage";

class DualStorage implements IFileStorage {
  constructor(
    private disk: DiskStorage,
    private s3: S3Storage,
  ) {}

  async saveFile(path: string, buffer: Buffer): Promise<void> {
    await Promise.all([this.disk.saveFile(path, buffer), this.s3.saveFile(path, buffer)]);
  }

  async readFile(path: string): Promise<Buffer> {
    try {
      // Try S3 first
      return await this.s3.readFile(path);
    } catch {
      // Fallback to disk
      return await this.disk.readFile(path);
    }
  }

  // ... implement other methods ...
}
```

## Post-Migration Steps

### 1. Verify Data Integrity

```bash
# Check file count
aws s3 ls s3://proplet-files-prod/ --recursive --summarize

# Download and verify a file
aws s3 cp s3://proplet-files-prod/{path} ./verify.txt
md5sum ./verify.txt
```

### 2. Enable Versioning

```bash
# Enable S3 versioning for recovery
aws s3api put-bucket-versioning \
  --bucket proplet-files-prod \
  --versioning-configuration Status=Enabled
```

### 3. Setup Monitoring

```bash
# Enable access logging
# AWS Console → S3 → Bucket → Properties → Server access logging
```

### 4. Cleanup (Optional)

```bash
# After confirming all files in S3:
# Remove old disk files
rm -rf uploads/

# Or keep as backup:
tar -czf uploads-backup.tar.gz uploads/
```

## Rollback Plan

If issues occur, rollback to disk storage:

```bash
# 1. Update .env
STORAGE_TYPE=disk

# 2. Restart application
npm run dev

# 3. Old files still on disk
```

Takes <5 minutes. Zero data loss.

## Testing Migration

### Before Migration

```bash
# Create test file
curl -X POST \
  -F "file=@document.pdf" \
  http://localhost:3000/files

# Note the file ID
export FILE_ID="..."
```

### After Migration

```bash
# Download test file
curl "http://localhost:3000/files/$FILE_ID?download=true" -o test-download.pdf

# Verify it's the same
md5sum document.pdf test-download.pdf
```

Both should match.

## Performance Testing

### Before (Disk)

```bash
# Upload speed test
time curl -X POST -F "file=@largefile.zip" http://localhost:3000/files

# Download speed test
time curl "http://localhost:3000/files/{fileId}?download=true" -o /dev/null
```

### After (S3)

```bash
# Same tests - compare speeds
# S3 may be slightly slower due to network, but gains availability
```

## Cost Analysis

**Before (Disk):**

```
Storage:  Free (disk space included)
Backup:   Manual effort (~$0)
Total:    Free (hidden costs in manual ops)
```

**After (S3):**

```
1GB storage:      1 × $0.023 = $0.023
100 uploads:      100 × $0.0004 = $0.04
1000 downloads:   1 × $0.09 = $0.09
────────────────────────────────
Total per month:  ~$0.16
```

**Cost for 1 year:**

```
1 year × $0.16/month = ~$2/year
+ Data transfer costs (minimal)
= ~$2-5/year
```

## Common Issues

### "Access Denied" During Migration

```bash
# Check IAM policy
aws iam get-user-policy --user-name proplet-app --policy-name s3-access

# Verify permissions include:
# - s3:GetObject
# - s3:PutObject
# - s3:DeleteObject
# - s3:ListBucket
```

### "SlowDown" Errors

```bash
# Add exponential backoff in migration script
// In migration script:
async function uploadWithRetry(s3, path, buffer, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await s3.saveFile(path, buffer);
      return;
    } catch (e) {
      if (i < maxRetries - 1) {
        const delay = Math.pow(2, i) * 100; // Exponential backoff
        await new Promise(r => setTimeout(r, delay));
      } else throw e;
    }
  }
}
```

### "File Not Found" After Switch

```bash
# Check both locations during transition period
aws s3 ls s3://proplet-files-prod/ --recursive --summarize
ls -la uploads/

# Should have files in one location
```

## Monitoring Post-Migration

### CloudWatch Metrics

```bash
# Monitor S3 operations
# AWS Console → CloudWatch → Dashboards

# Key metrics:
# - 4xxErrors (access issues)
# - 5xxErrors (service issues)
# - BucketSizeBytes (storage used)
# - NumberOfObjects (file count)
```

### Application Logs

```bash
# Monitor application for S3 errors
# npm run dev 2>&1 | grep -i "s3\|storage\|error"
```

## Documentation

| Document                   | Purpose                   |
| -------------------------- | ------------------------- |
| S3_SETUP.md                | Step-by-step AWS setup    |
| STORAGE_CONFIGURATION.md   | Storage options and setup |
| STORAGE_QUICK_REFERENCE.md | Quick reference card      |
| FILE_MANAGEMENT.md         | File management overview  |

## Support

For AWS S3:

- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/)
- [AWS Support](https://console.aws.amazon.com/support/)

For Proplet:

- See: `FILE_MANAGEMENT.md`
- See: `docs/`

## Migration Checklist

- [ ] AWS account ready
- [ ] S3 bucket created
- [ ] IAM user created with permissions
- [ ] Access keys saved securely
- [ ] npm install @aws-sdk/client-s3
- [ ] .env updated with S3 config
- [ ] Application restarted
- [ ] Test file uploaded successfully
- [ ] Test file downloaded successfully
- [ ] Monitor application logs
- [ ] Enable S3 versioning (optional)
- [ ] Setup backups/disaster recovery
- [ ] Document S3 bucket details
- [ ] Inform team of storage change
- [ ] Old files backed up (optional)

## Timeline Estimate

| Activity           | Duration                     |
| ------------------ | ---------------------------- |
| AWS Setup          | 15 min                       |
| Application Update | 5 min                        |
| Testing            | 10 min                       |
| Data Migration     | 1-48 hours (depends on size) |
| Verification       | 30 min                       |
| **Total**          | **2 hours - 2 days**         |

## Success Criteria

✅ Files upload successfully to S3
✅ Files download successfully from S3
✅ File metadata accessible
✅ File deletion works
✅ List operation works
✅ Performance acceptable
✅ No data loss
✅ All monitoring active

Once all criteria met, migration is complete!

---

**Ready to migrate?** Start with [docs/S3_SETUP.md](./docs/S3_SETUP.md) →
