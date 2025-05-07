import type { Context } from "hono";

import { eq } from "drizzle-orm";

import dbContext from "../../infrastructure/dbContext.js";
import { locations } from "../../infrastructure/schema/locations.js";

export const saveLocationsCommand = async (c: Context) => {
  try {
    await dbContext.transaction(async (tx) => {
      await tx
        .delete(locations)
        .where(eq(locations.tenantId, "01976ed4-b771-700a-b1e8-a1e898e5451d"));

      await tx.insert(locations).values([
        {
          id: "01976ed4-b771-700a-b1e8-a1e898e54511",
          publicId: 1,
          name: "example condition",
          tenantId: "01976ed4-b771-700a-b1e8-a1e898e5451d",
        },
        {
          id: "01976ed4-b771-700a-b1e8-a1e898e54512",
          publicId: 2,
          name: "another example condition",
          tenantId: "01976ed4-b771-700a-b1e8-a1e898e5451d",
        },
      ]);
    });

    return c.json(true);
  } catch (error) {
    return c.json(error);
  }
};
