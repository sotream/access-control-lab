import type { NextConfig } from "next";

const config: NextConfig = {
  poweredByHeader: false,
  // external: one instance of each in the Node module cache. Bundled, openid-client could end up as one copy per route bundle, and a Configuration made by one copy is refused by another ("config must be an instance of Configuration"), depending on which route ran first.
  serverExternalPackages: ["pg", "openid-client"],
  async headers() {
    // static assets bypass proxy.ts (they carry no nonce and no user data), so their hardening headers live here
    return [
      {
        source: "/_next/static/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
          { key: "Referrer-Policy", value: "same-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
        ],
      },
    ];
  },
};
export default config;
