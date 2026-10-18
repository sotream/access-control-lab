// Route inventory: every controller method that carries a route, with the access it declares.
import { type Type } from "@nestjs/common";
import { METHOD_METADATA, PATH_METADATA } from "@nestjs/common/constants";
import { ModulesContainer, Reflector } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { ACCESS_KEY, type Access } from "../src/auth/access.js";

export interface RouteInfo {
  method: number;
  path: string;
  access: Access | undefined;
}

/** Walks every controller method that carries a route and reads its declared access. */
export function enumerate(app: NestExpressApplication): RouteInfo[] {
  const reflector = new Reflector();
  const out: RouteInfo[] = [];
  for (const mod of app.get(ModulesContainer).values()) {
    for (const wrapper of mod.controllers.values()) {
      const ctor = wrapper.metatype as Type | null;
      if (!ctor) continue;
      const base = Reflect.getMetadata(PATH_METADATA, ctor) as string;
      for (const name of Object.getOwnPropertyNames(ctor.prototype).filter((n) => n !== "constructor")) {
        const handler = ctor.prototype[name] as (...a: never[]) => unknown;
        const path = Reflect.getMetadata(PATH_METADATA, handler) as string | undefined;
        if (typeof handler !== "function" || path === undefined) continue;
        out.push({
          method: Reflect.getMetadata(METHOD_METADATA, handler) as number,
          path: `/${base}/${path}`.replace(/\/+/g, "/").replace(/\/$/, "") || "/",
          access: reflector.getAllAndOverride<Access | undefined>(ACCESS_KEY, [handler, ctor]),
        });
      }
    }
  }
  return out;
}

