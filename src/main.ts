import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { logger } from "hono/logger";
import { requestId } from "hono/request-id";

const app = new Hono();

app.use("*", requestId());
app.use(logger());

app.get("/", async (c) => {
  const result = {
    status: "ok",
  };

  return c.json(result);
});

serve(
  {
    fetch: app.fetch,
    port: 3000,
  },
  (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
  },
);
