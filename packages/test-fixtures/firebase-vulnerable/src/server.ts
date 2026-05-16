import express from "express";

const app = express();

app.get("/api/private/profile", async (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  const decoded = JSON.parse(Buffer.from((token ?? "").split(".")[1], "base64").toString("utf8"));
  res.json({ uid: decoded.sub });
});

