"use client";

import { useSession } from "next-auth/react";

export default function AdminPage() {
  const { data } = useSession();
  if (data?.user?.role !== "admin") return null;
  return <div>Admin</div>;
}

