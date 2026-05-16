import { auth } from "@/auth";
import { db } from "@/db";

export async function GET(_: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });

  const project = await db.project.findFirst({
    where: {
      id: params.id,
      members: { some: { userId: session.user.id } }
    }
  });

  if (!project) return new Response("Not found", { status: 404 });
  return Response.json(project);
}

