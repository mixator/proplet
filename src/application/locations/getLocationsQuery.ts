import type { Context } from "hono";

import dbContext from "../../infrastructure/dbContext.js";

export const getLocationsQuery = async (c: Context) => {
  const result = await dbContext.query.locations.findMany({
    where: ({ tenantId }, { eq }) =>
      eq(tenantId, "01976ed4-b771-700a-b1e8-a1e898e5451d"),
  });

  return c.json(result);
};
