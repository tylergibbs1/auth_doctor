import { auth } from "@/auth";
import { db } from "@/db";

export async function GET(_: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session?.user) return new Response("Unauthorized", { status: 401 });

  return Response.json(await db.project.findUnique({ where: { id: params.id } }));
}

