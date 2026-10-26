import { Buffer } from "node:buffer";
import { createHash, createPrivateKey, createPublicKey, randomUUID, sign } from "node:crypto";
import { GATE_LOGOUT_FIXTURE } from "../e2e/mockArkretApi";
import type { driveOnce } from "./mockShapeDriver";

type ProofOptions = {
  seed?: Buffer;
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  target?: { operation: string; url: string };
  body?: unknown;
};

// This is the harness's DPoP device, not its separate event-signing key.
export function gateLogoutRequest(options: ProofOptions = {}): Parameters<typeof driveOnce>[1] {
  const target = options.target ?? GATE_LOGOUT_FIXTURE;
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), options.seed ?? Buffer.alloc(32)]),
    format: "der", type: "pkcs8",
  });
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const header = encode({ alg: "Ed25519", jwk: createPublicKey(privateKey).export({ format: "jwk" }), typ: "dpop+jwt", ...options.header });
  const claims = encode({
    ath: createHash("sha256").update(GATE_LOGOUT_FIXTURE.grant).digest("base64url"),
    htm: "POST", htu: target.url, iat: Math.floor(Date.now() / 1000),
    jti: `urn:uuid:${randomUUID()}`, ...options.claims,
  });
  const input = `${header}.${claims}`;
  return {
    method: "POST", url: target.url, postData: options.body ?? {},
    headers: {
      "arkret-operation": target.operation,
      "content-type": "application/json",
      authorization: `DPoP ${GATE_LOGOUT_FIXTURE.grant}`,
      dpop: `${input}.${sign(null, Buffer.from(input), privateKey).toString("base64url")}`,
    },
  };
}
