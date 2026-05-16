import { jwtVerify } from "jose";

export async function verifyToken(token: string, secret: Uint8Array) {
  return jwtVerify(token, secret, {
    issuer: "https://issuer.example.com",
    audience: "app-api"
  });
}

