import type { NextConfig } from "next";

const config: NextConfig = {
  poweredByHeader: false,
  serverExternalPackages: ["pg"],
  async headers() {
    // static assets bypass proxy.ts (they carry no nonce and no user data), so their hardening headers live here
    return [
      {
        source: "/_next/static/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
          { key: "Referrer-Policy", value: "no-referrer" },
        ],
      },
    ];
  },
};
export default config;
