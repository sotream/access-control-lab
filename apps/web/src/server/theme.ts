import { cookies } from "next/headers";
import { themeCookieName } from "./cookies";

export type Theme = "light" | "dark" | "system";
export const parseTheme = (v: unknown): Theme => (v === "light" || v === "dark" ? v : "system");

/** The stored preference. Anything but light or dark means "follow the system". */
export async function currentTheme(): Promise<Theme> {
  return parseTheme((await cookies()).get(themeCookieName())?.value);
}
