CREATE TABLE "Condition" (
	"id" uuid,
	"publicId" integer,
	"name" varchar(255) NOT NULL,
	"tenantId" uuid
);
--> statement-breakpoint
CREATE TABLE "DamageLocation" (
	"id" uuid,
	"publicId" integer,
	"name" varchar(255) NOT NULL,
	"tenantId" uuid
);
--> statement-breakpoint
CREATE TABLE "files" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"name" text NOT NULL,
	"mimeType" text NOT NULL,
	"size" integer NOT NULL,
	"path" text NOT NULL,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL,
	"tenantId" uuid NOT NULL
);
--> statement-breakpoint
CREATE TABLE "Location" (
	"id" uuid,
	"publicId" integer,
	"name" varchar(255) NOT NULL,
	"tenantId" uuid
);
--> statement-breakpoint
CREATE TABLE "Tenant" (
	"id" uuid,
	"name" varchar(255) NOT NULL
);
--> statement-breakpoint
ALTER TABLE "Condition" ADD CONSTRAINT "Condition_tenantId_Tenant_id_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id");--> statement-breakpoint
ALTER TABLE "DamageLocation" ADD CONSTRAINT "DamageLocation_tenantId_Tenant_id_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id");--> statement-breakpoint
ALTER TABLE "files" ADD CONSTRAINT "files_tenantId_Tenant_id_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id");--> statement-breakpoint
ALTER TABLE "Location" ADD CONSTRAINT "Location_tenantId_Tenant_id_fkey" FOREIGN KEY ("tenantId") REFERENCES "Tenant"("id");