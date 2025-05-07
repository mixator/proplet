import * as z from "zod";

const condition = z.object({
  publicId: z.number().int(),
  name: z.string().min(1).max(255),
});

export type Condition = z.infer<typeof condition>;
