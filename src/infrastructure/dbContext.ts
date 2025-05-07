import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import * as schema from "./schema/index.js";

const queryClient = postgres("");
const dbContext = drizzle({
  client: queryClient,
  schema: schema,
});

export default dbContext;
