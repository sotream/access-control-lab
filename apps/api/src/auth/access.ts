import { SetMetadata } from "@nestjs/common";

export const ACCESS_KEY = "acl:access";

/** Declared access of a route. Stage 4 adds a `policy` kind; a route with none of these is denied. */
export type Access = { kind: "public" } | { kind: "authenticated" };

/** No authentication. Allowed for /health only; a test pins that list. */
export const Public = () => SetMetadata(ACCESS_KEY, { kind: "public" } satisfies Access);

/** Valid access token required, no further decision (identity-only routes). */
export const Authenticated = () => SetMetadata(ACCESS_KEY, { kind: "authenticated" } satisfies Access);
