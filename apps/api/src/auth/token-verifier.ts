import { Inject, Injectable } from "@nestjs/common";
import { createRemoteJWKSet, decodeProtectedHeader, errors, jwtVerify, type JWTVerifyGetKey } from "jose";
import { CONFIG, type AppConfig } from "../config.js";
import { PrincipalError, toPrincipal, type Principal } from "./principal.js";

/** Only asymmetric algorithms. `none` and every HS* are rejected by omission. */
export const ALLOWED_ALGS = ["RS256", "ES256"];

/** Machine readable, safe to log. Never carries token or claim contents. */
export type AuthFailure =
  | "malformed"
  | "missing_kid"
  | "alg_not_allowed"
  | "unknown_key"
  | "bad_signature"
  | "expired"
  | "not_yet_valid"
  | "bad_issuer"
  | "bad_audience"
  | "wrong_token_type"
  | "bad_azp"
  | "bad_claims"
  | "jwks_unavailable";

export class AuthError extends Error {
  constructor(readonly reason: AuthFailure) {
    super(reason);
  }
}

@Injectable()
export class TokenVerifier {
  private readonly keys: JWTVerifyGetKey;

  constructor(@Inject(CONFIG) private readonly cfg: AppConfig) {
    // jose caches the set for cacheMaxAge and refetches on an unknown kid at most once per cooldownDuration,
    // so a flood of tokens with random kids cannot turn into a flood of requests to Keycloak.
    this.keys = createRemoteJWKSet(new URL(cfg.jwksUri), {
      cooldownDuration: cfg.jwksCooldownMs,
      cacheMaxAge: cfg.jwksMaxAgeMs,
      timeoutDuration: 5_000,
    });
  }

  async verify(token: string): Promise<Principal> {
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AuthError("malformed");
    }
    if (typeof header.alg !== "string" || !ALLOWED_ALGS.includes(header.alg)) throw new AuthError("alg_not_allowed");
    // Keycloak always sets kid; a token without one is never matched against "the only key"
    if (typeof header.kid !== "string" || header.kid === "") throw new AuthError("missing_kid");

    let payload;
    try {
      ({ payload } = await jwtVerify(token, this.keys, {
        algorithms: ALLOWED_ALGS,
        issuer: this.cfg.issuer,
        audience: this.cfg.audience,
        clockTolerance: this.cfg.clockSkewSeconds,
        requiredClaims: ["exp", "iat", "sub", "iss", "aud"],
      }));
    } catch (e) {
      throw new AuthError(classify(e));
    }

    // Keycloak marks access tokens `typ: Bearer`; ID tokens carry `ID`, refresh tokens `Refresh`.
    if (payload.typ !== "Bearer") throw new AuthError("wrong_token_type");
    if (typeof payload.azp !== "string" || !this.cfg.allowedAzp.includes(payload.azp)) throw new AuthError("bad_azp");

    try {
      return toPrincipal(payload as Record<string, unknown>);
    } catch (e) {
      if (e instanceof PrincipalError) throw new AuthError("bad_claims");
      throw e;
    }
  }
}

function classify(e: unknown): AuthFailure {
  if (e instanceof errors.JWTExpired) return "expired";
  if (e instanceof errors.JWTClaimValidationFailed) {
    if (e.claim === "iss") return "bad_issuer";
    if (e.claim === "aud") return "bad_audience";
    if (e.claim === "nbf") return "not_yet_valid";
    return "bad_claims";
  }
  if (e instanceof errors.JWKSNoMatchingKey) return "unknown_key";
  if (e instanceof errors.JWKSMultipleMatchingKeys) return "unknown_key";
  if (e instanceof errors.JWSSignatureVerificationFailed) return "bad_signature";
  if (e instanceof errors.JOSEAlgNotAllowed) return "alg_not_allowed";
  if (e instanceof errors.JWKSTimeout || e instanceof errors.JWKSInvalid) return "jwks_unavailable";
  if (e instanceof errors.JOSEError) return "malformed";
  // network failure fetching the JWKS surfaces as a plain error: still a refusal, never an allow
  return "jwks_unavailable";
}
