import { Controller, Get } from "@nestjs/common";
import { Authenticated } from "./auth/access.js";
import type { Principal } from "./auth/principal.js";
import { CurrentPrincipal } from "./http/request.js";

/** Identity echo: what the API understood from the token. Used by the BFF and by the integration tests. */
@Controller("me")
export class MeController {
  @Authenticated()
  @Get()
  get(@CurrentPrincipal() p: Principal) {
    return p;
  }
}
