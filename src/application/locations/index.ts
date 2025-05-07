import { Hono } from "hono";

import { getLocationsQuery } from "./getLocationsQuery.js";
import { saveLocationsCommand } from "./saveLocationsCommand.js";

const locationsApi = new Hono();

locationsApi.get("/getLocations", getLocationsQuery);
locationsApi.get("/saveLocations", saveLocationsCommand);
locationsApi.get("/saveLocationsEx", saveLocationsCommand);

export default locationsApi;
