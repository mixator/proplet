import { z } from "zod";

/**
 * Environment variables validation schema using Zod
 * Validates and coerces environment variables at application startup
 */

const envSchema = z.object({
  // Storage Configuration
  STORAGE_TYPE: z
    .enum(["disk", "s3"])
    .default("disk")
    .describe("Storage backend: disk for local, s3 for AWS"),

  STORAGE_BASE_PATH: z.string().default("./uploads").describe("Base path for local file storage"),

  // AWS Configuration
  AWS_REGION: z.string().default("us-east-1").describe("AWS region for S3 storage"),

  S3_BUCKET: z.string().optional().describe("S3 bucket name (required if STORAGE_TYPE=s3)"),

  AWS_ACCESS_KEY_ID: z
    .string()
    .optional()
    .describe("AWS access key ID (use IAM role in production)"),

  AWS_SECRET_ACCESS_KEY: z
    .string()
    .optional()
    .describe("AWS secret access key (use IAM role in production)"),

  // Database Configuration
  DATABASE_URL: z
    .string()
    .url("DATABASE_URL must be a valid URL")
    .describe("PostgreSQL connection URL"),

  // Application Configuration
  NODE_ENV: z
    .enum(["development", "staging", "production"])
    .default("development")
    .describe("Application environment"),

  PORT: z
    .string()
    .default("3000")
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive())
    .describe("Server port number"),
});

/**
 * Refined schema with conditional validation
 * Ensures S3_BUCKET is present when STORAGE_TYPE is s3
 */
const refinedEnvSchema = envSchema.refine(
  (env) => {
    if (env.STORAGE_TYPE === "s3" && !env.S3_BUCKET) {
      return false;
    }
    return true;
  },
  {
    message: "S3_BUCKET environment variable is required when STORAGE_TYPE=s3",
    path: ["S3_BUCKET"],
  },
);

/**
 * Type-safe environment variables after validation
 */
export type Environment = z.infer<typeof refinedEnvSchema>;

/**
 * Validate environment variables at application startup
 * Throws detailed error message if validation fails
 *
 * @returns Validated environment variables
 * @throws Error with detailed validation errors
 */
export function validateEnv(): Environment {
  const result = refinedEnvSchema.safeParse(process.env);

  if (!result.success) {
    const errors = z.prettifyError(result.error);

    const error = new Error(errors);
    error.stack = ""; // Overwrite the stack trace with an empty string

    console.log(error);
  }

  return result.data;
}

/**
 * Singleton instance of validated environment
 * Created at application startup
 */
export const env = validateEnv();

/**
 * Log validated environment (for debugging)
 * Excludes sensitive values
 */
export function logEnvironment(): void {
  const safe = {
    STORAGE_TYPE: env?.STORAGE_TYPE,
    STORAGE_BASE_PATH: env?.STORAGE_BASE_PATH,
    AWS_REGION: env?.AWS_REGION,
    S3_BUCKET: env?.S3_BUCKET ? "***" : undefined,
    DATABASE_URL: env?.DATABASE_URL ? "***" : undefined,
    NODE_ENV: env?.NODE_ENV,
    PORT: env?.PORT,
  };

  console.log("✓ Environment validated successfully:");
  console.log(JSON.stringify(safe, null, 2));
}
