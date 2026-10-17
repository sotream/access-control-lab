import { Controller, Get } from "@nestjs/common";
import { Public } from "./auth/access.js";

@Controller("health")
export class HealthController {
  @Public()
  @Get()
  get() {
    return { status: "ok" };
  }
}
