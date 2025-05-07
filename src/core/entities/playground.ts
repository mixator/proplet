import * as z from "zod";

const condition = z.object({
  publicId: z.number().int(),
  name: z.string().min(1).max(255),
});

const location = z.object({
  publicId: z.number().int(),
  secret: z.string().min(1).max(255),
});

enum NeedleType {
  condition,
  location,
}

function transformData(
  type: NeedleType.condition,
  payload: unknown,
): z.infer<typeof condition>;
function transformData(
  type: NeedleType.location,
  payload: unknown,
): z.infer<typeof location>;
function transformData(type: NeedleType, payload: unknown) {
  switch (type) {
    case NeedleType.condition:
      return condition.parse(payload);
    case NeedleType.location:
      return location.parse(payload);
    default:
      throw new Error(`Unknown type`);
  }
}

const cData = transformData(NeedleType.condition, { prop: 1 });
console.log(cData);
// const lData = transformData(NeedleType.location, { prop: 1 });
