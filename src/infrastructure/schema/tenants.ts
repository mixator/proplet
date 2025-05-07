import { relations } from "drizzle-orm";
import { pgTable, uuid, varchar } from "drizzle-orm/pg-core";

import { conditions } from "./conditions.js";
import { damageLocations } from "./damageLocations.js";
import { locations } from "./locations.js";

export const tenants = pgTable("Tenant", {
  id: uuid(),
  name: varchar({
    length: 255,
  }).notNull(),
});

export const tenantsRelations = relations(tenants, ({ many }) => ({
  conditions: many(conditions),
  damageLocations: many(damageLocations),
  locations: many(locations),
}));
