import { getContext } from "hono/context-storage";

type Env = {
  Variables: {
    tenantId: string;
  };
};

export const currentTenantId = () => {
  return getContext<Env>().var.tenantId;
};
