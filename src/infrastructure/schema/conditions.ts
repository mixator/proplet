import { relations } from "drizzle-orm";
import { integer, pgTable, uuid, varchar } from "drizzle-orm/pg-core";

import { tenants } from "./tenants.js";

export const conditions = pgTable("Condition", {
  id: uuid(),
  publicId: integer(),
  name: varchar({
    length: 255,
  }).notNull(),
  tenantId: uuid().references(() => tenants.id),
});

export const conditionsRelations = relations(conditions, ({ one }) => ({
  tenant: one(tenants, {
    fields: [conditions.tenantId],
    references: [tenants.id],
  }),
}));
