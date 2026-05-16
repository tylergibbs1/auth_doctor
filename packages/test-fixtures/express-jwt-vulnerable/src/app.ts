import express from "express";
import jwt from "jsonwebtoken";
import { db } from "./db";

const app = express();
app.use(express.json());

app.post("/admin/users/:id/delete", deleteUser);
app.get("/api/private/projects/:id", async (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const user = jwt.decode(token ?? "");
  const project = await db.project.findUnique({ where: { id: req.params.id } });
  res.json({ user, project });
});

app.use(requireAuth);

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!req.headers.authorization) return res.status(401).end();
  next();
}

function deleteUser(req: express.Request, res: express.Response) {
  db.user.delete({ where: { id: req.params.id } });
  res.status(204).end();
}

