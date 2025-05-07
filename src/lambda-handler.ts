import { handle } from "hono/aws-lambda";

import app from "./main.js";

export const handler = handle(app);
