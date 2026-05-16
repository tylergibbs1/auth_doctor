import { cookies } from "next/headers";

export async function POST(req: Request) {
  if (req.headers.get("origin") !== "https://example.com") {
    return new Response("Forbidden", { status: 403 });
  }
  cookies().set("session", "opaque", {
    httpOnly: true,
    secure: true,
    sameSite: "lax"
  });
  return new Response("ok");
}

