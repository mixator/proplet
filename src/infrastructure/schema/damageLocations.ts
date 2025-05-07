import { relations } from "drizzle-orm";
import { integer, pgTable, uuid, varchar } from "drizzle-orm/pg-core";

import { tenants } from "./tenants.js";

export const damageLocations = pgTable("DamageLocation", {
  id: uuid(),
  publicId: integer(),
  name: varchar({
    length: 255,
  }).notNull(),
  tenantId: uuid().references(() => tenants.id),
});

export const damageLocationsRelations = relations(
  damageLocations,
  ({ one }) => ({
    tenant: one(tenants, {
      fields: [damageLocations.tenantId],
      references: [tenants.id],
    }),
  }),
);
