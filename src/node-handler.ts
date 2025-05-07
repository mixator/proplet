import { serve } from "@hono/node-server";

import dbContext from "./infrastructure/dbContext.js";
import app from "./main.js";

const server = serve(app, (info) => {
  console.log(`Listening on http://localhost:${info.port}`); // Listening on http://localhost:3000
});

process.on("SIGINT", async () => {
  console.log("Received SIGINT signal");
  await dbContext.$client.end();
  server.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("Received SIGTERM signal");
  await dbContext.$client.end();
  server.close((err) => {
    if (err) {
      console.error(err);
      process.exit(1);
    }
    process.exit(0);
  });
});
