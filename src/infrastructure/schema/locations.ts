import { relations } from "drizzle-orm";
import { integer, pgTable, uuid, varchar } from "drizzle-orm/pg-core";

import { tenants } from "./tenants.js";

export const locations = pgTable("Location", {
  id: uuid(),
  publicId: integer(),
  name: varchar({
    length: 255,
  }).notNull(),
  tenantId: uuid().references(() => tenants.id),
});

export const locationsRelations = relations(locations, ({ one }) => ({
  tenant: one(tenants, {
    fields: [locations.tenantId],
    references: [tenants.id],
  }),
}));
