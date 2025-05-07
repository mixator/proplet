import type { Context } from "hono";

import dbContext from "../../infrastructure/dbContext.js";
import { currentTenantId } from "../../infrastructure/sessionContext.js";

export const getConditionsQuery = async (c: Context) => {
  const result = await dbContext.query.conditions.findMany({
    where: ({ tenantId }, { eq }) => eq(tenantId, currentTenantId()),
  });

  return c.json(result);
};
