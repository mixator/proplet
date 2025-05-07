import { Hono } from "hono";

import { getConditionsQuery } from "./getConditionsQuery.js";
import { saveConditionsCommand } from "./saveConditionsCommand.js";

const conditionsApi = new Hono();

conditionsApi.get("/", getConditionsQuery);
conditionsApi.post("/", saveConditionsCommand);

export default conditionsApi;
