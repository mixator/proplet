import { Hono } from "hono";
import { contextStorage } from "hono/context-storage";
import { logger } from "hono/logger";
import { trimTrailingSlash } from "hono/trailing-slash";

import { validateEnv, logEnvironment } from "#infrastructure/env";
import conditionsApi from "#rest-api/conditions/index";
import locationsApi from "#rest-api/locations/index";

// Validate environment variables at startup
// This will throw and exit if any required variables are missing
validateEnv();
logEnvironment();

type Env = {
  Variables: {
    tenantId: string;
  };
};

const app = new Hono<Env>({
  strict: true,
});

// Middleware stack
app.use(logger());
app.use(trimTrailingSlash());
app.use(contextStorage());

// Set tenant context
app.use(async (c, next) => {
  c.set("tenantId", "01976ed4-b771-700a-b1e8-a1e898e5451d");
  await next();
});

app.route("/conditions", conditionsApi);
app.route("/locations", locationsApi);

export default app;
