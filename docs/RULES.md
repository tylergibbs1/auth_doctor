# Auth Doctor Rules

Each rule is intentionally narrow in the MVP. Critical and error findings should be actionable, code-oriented, and suppressible only at the smallest useful scope.

## Authentication

### `auth/no-server-auth-check`

Unsafe:

```ts
export async function GET() {
  return Response.json(await db.project.findMany());
}
```

Safe:

```ts
export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
  return Response.json(await db.project.findMany({ where: { ownerId: session.user.id } }));
}
```

### `auth/client-only-protection`

Unsafe:

```tsx
"use client";
const { data } = useSession();
if (!data) redirect("/login");
```

Safe:

```ts
const session = await auth();
if (!session?.user) redirect("/login");
```

### `auth/unprotected-admin-route`

Unsafe:

```ts
app.post("/admin/users/:id/delete", deleteUser);
```

Safe:

```ts
app.post("/admin/users/:id/delete", requireAuth, requireAdmin, deleteUser);
```

## Authorization

### `auth/authenticated-not-authorized`

Unsafe:

```ts
const session = await auth();
if (!session?.user) return unauthorized();
return db.project.findUnique({ where: { id: params.id } });
```

Safe:

```ts
return db.project.findFirst({
  where: { id: params.id, members: { some: { userId: session.user.id } } }
});
```

### `auth/trusts-client-role`

Unsafe:

```ts
const { role } = req.body;
if (role === "admin") await deleteUser();
```

Safe:

```ts
const actor = await getCurrentUser(req);
if (!actor.roles.includes("admin")) return forbidden();
```

### `auth/missing-tenant-scope`

Unsafe:

```ts
return db.invoice.findMany({ where: { status: "open" } });
```

Safe:

```ts
return db.invoice.findMany({ where: { orgId: session.orgId, status: "open" } });
```

### `auth/insecure-direct-object-reference`

Unsafe:

```ts
return db.file.findUnique({ where: { id: req.params.id } });
```

Safe:

```ts
return db.file.findFirst({ where: { id: req.params.id, ownerId: user.id } });
```

### `auth/admin-claim-not-verified-server-side`

Unsafe:

```tsx
if (session.user.role === "admin") return <DeleteUserButton />;
```

Safe:

```ts
await requireAdmin();
await deleteUser(params.id);
```

## JWT

### `auth/jwt-not-verified`

Unsafe:

```ts
const claims = jwt.decode(token);
```

Safe:

```ts
const claims = await jwtVerify(token, secret, { issuer, audience });
```

### `auth/jwt-none-or-weak-alg`

Unsafe:

```ts
jwt.verify(token, secret, { algorithms: [req.query.alg] });
```

Safe:

```ts
jwt.verify(token, secret, { algorithms: ["RS256"] });
```

### `auth/jwt-missing-exp`

Unsafe:

```ts
jwt.verify(token, secret);
```

Safe:

```ts
jwt.verify(token, secret, { maxAge: "15m" });
```

### `auth/jwt-missing-audience-issuer`

Unsafe:

```ts
await jwtVerify(token, key);
```

Safe:

```ts
await jwtVerify(token, key, { issuer: "https://issuer.example.com", audience: "app-api" });
```

### `auth/jwt-secret-client-exposed`

Unsafe:

```tsx
"use client";
const secret = process.env.NEXT_PUBLIC_JWT_SECRET;
```

Safe:

```ts
const secret = process.env.JWT_SECRET;
```

Keep the safe form in server-only modules.

## Cookies And Sessions

### `auth/insecure-cookie-flags`

Unsafe:

```ts
res.cookie("session", sessionId);
```

Safe:

```ts
res.cookie("session", sessionId, { httpOnly: true, secure: true, sameSite: "lax" });
```

### `auth/localstorage-token`

Unsafe:

```ts
localStorage.setItem("access_token", token);
```

Safe:

```ts
cookies().set("session", opaqueSessionId, { httpOnly: true, secure: true, sameSite: "lax" });
```

### `auth/long-session-ttl`

Unsafe:

```ts
session: { maxAge: 60 * 60 * 24 * 365 }
```

Safe:

```ts
session: { maxAge: 60 * 60 * 24 * 7 }
```

### `auth/session-fixation-risk`

Unsafe:

```ts
await login(user);
res.cookie("session", existingSessionId);
```

Safe:

```ts
await req.session.regenerate();
res.cookie("session", newSessionId, hardenedCookieOptions);
```

### `auth/cookie-domain-too-broad`

Unsafe:

```ts
res.cookie("session", id, { domain: ".example.com" });
```

Safe:

```ts
res.cookie("session", id, { httpOnly: true, secure: true, sameSite: "lax" });
```

## CSRF And OAuth

### `auth/missing-csrf-state-changing-route`

Unsafe:

```ts
app.post("/settings", requireSessionCookie, updateSettings);
```

Safe:

```ts
app.post("/settings", requireSessionCookie, validateCsrfToken, updateSettings);
```

### `auth/oauth-missing-state`

Unsafe:

```ts
return redirect(`${issuer}/authorize?client_id=${clientId}`);
```

Safe:

```ts
const state = await createOAuthStateCookie();
return redirect(`${issuer}/authorize?client_id=${clientId}&state=${state}`);
```

### `auth/oauth-open-redirect`

Unsafe:

```ts
return redirect(req.query.callbackUrl);
```

Safe:

```ts
return redirect(allowlistedRelativePath(req.query.callbackUrl) ?? "/dashboard");
```

### `auth/oauth-missing-pkce`

Unsafe:

```ts
return redirect(`${issuer}/authorize?response_type=code&client_id=${clientId}`);
```

Safe:

```ts
return redirect(`${issuer}/authorize?response_type=code&code_challenge=${challenge}&code_challenge_method=S256`);
```

## Provider-Specific Misuse

### `auth/authjs-unsafe-callback-role`

Unsafe:

```ts
session.user.role = token.role;
```

Safe:

```ts
session.user.role = await lookupRoleFromDatabase(session.user.id);
```

### `auth/clerk-client-only-auth`

Unsafe:

```tsx
const { isSignedIn } = useAuth();
return isSignedIn ? <PrivateData /> : null;
```

Safe:

```ts
const { userId, orgId } = auth();
if (!userId) return unauthorized();
```

### `auth/supabase-service-key-exposed`

Unsafe:

```ts
createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
```

Safe:

```ts
createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);
```

Only use the safe form in server-only modules.

### `auth/supabase-rls-disabled`

Unsafe:

```sql
create table public.projects (id uuid primary key, owner_id uuid);
```

Safe:

```sql
create table public.projects (id uuid primary key, owner_id uuid);
alter table public.projects enable row level security;
create policy "owners can read" on public.projects for select using (auth.uid() = owner_id);
```

### `auth/firebase-id-token-not-verified`

Unsafe:

```ts
const claims = JSON.parse(Buffer.from(token.split(".")[1], "base64").toString("utf8"));
```

Safe:

```ts
const claims = await getAuth().verifyIdToken(token);
```

## Middleware

### `auth/missing-middleware-coverage`

Unsafe:

```ts
export const config = { matcher: ["/dashboard/:path*"] };
```

Safe:

```ts
export const config = { matcher: ["/dashboard/:path*", "/admin/:path*", "/api/private/:path*"] };
```

### `auth/middleware-after-route`

Unsafe:

```ts
app.post("/admin/users/:id/delete", deleteUser);
app.use(requireAuth);
```

Safe:

```ts
app.use(requireAuth);
app.post("/admin/users/:id/delete", requireAdmin, deleteUser);
```

### `auth/next-middleware-matcher-gap`

Unsafe:

```ts
export const config = { matcher: ["/dashboard/:path*"] };
```

Safe:

```ts
export const config = { matcher: ["/dashboard/:path*", "/api/:path*"] };
```

### `auth/public-glob-too-broad`

Unsafe:

```ts
const publicRoutes = ["/**"];
```

Safe:

```ts
const publicRoutes = ["/", "/login", "/signup", "/api/webhooks/stripe"];
```

### `auth/express-missing-next-on-deny`

Unsafe:

```ts
if (!user) res.status(401).end();
next();
```

Safe:

```ts
if (!user) return res.status(401).end();
return next();
```

## Secrets

### `auth/service-key-in-client`

Unsafe:

```tsx
"use client";
const key = process.env.NEXT_PUBLIC_PROVIDER_ADMIN_KEY;
```

Safe:

```ts
const key = process.env.PROVIDER_ADMIN_KEY;
```

Keep the safe form inside server-only code.

### `auth/public-env-secret-name`

Unsafe:

```ts
process.env.NEXT_PUBLIC_JWT_SECRET;
```

Safe:

```ts
process.env.JWT_SECRET;
```

Do not expose signing, service, private, or admin secrets through public environment prefixes.

### `auth/hardcoded-auth-secret`

Unsafe:

```ts
const jwtSecret = "super-secret-value";
```

Safe:

```ts
const jwtSecret = process.env.JWT_SECRET!;
```

### `auth/weak-secret-length`

Unsafe:

```ts
const sessionSecret = "secret";
```

Safe:

```ts
const sessionSecret = process.env.SESSION_SECRET!;
```

Use a high-entropy value of at least 32 bytes.
