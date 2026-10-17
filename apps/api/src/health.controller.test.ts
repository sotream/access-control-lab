import { describe, expect, it } from "vitest";
import { HealthController } from "./health.controller.js";

describe("HealthController", () => {
  it("reports ok", () => {
    expect(new HealthController().get()).toEqual({ status: "ok" });
  });
});
