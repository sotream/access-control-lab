/** Fail fast: a server with a missing or unsafe configuration must not start, instead of failing on the first request. */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs" || process.env.NEXT_PHASE === "phase-production-build") return;
  const { config } = await import("./src/server/config");
  try {
    config();
  } catch (e) {
    // Next would keep serving 500s; a deployment should see a failed start instead
    console.error(JSON.stringify({ level: "error", msg: "invalid configuration, refusing to start", error: e instanceof Error ? e.message : String(e) }));
    process.exit(1);
  }
}
