import type { Diagnostic, Rule, RuleContext, SourceFile } from "@auth-doctor/types";

type RuleMeta = Pick<Rule, "id" | "title" | "category" | "defaultSeverity"> & {
  whyItMatters: string;
  recommendation: string;
  docs?: string[];
};

const dangerousPath = /(admin|dashboard|settings|account|billing|teams?|orgs?|organizations?|projects?|users?|api\/private|invitations?|files?|documents?|apikeys?)/i;
const databaseAccess = /\b(db|prisma|firebase|firestore|collection|model)\b[\s\S]{0,240}\.(find|findMany|findUnique|query|select|insert|update|delete|remove|create|upsert|get|set|doc)\b|\.from\(["'`][\w-]+["'`]\)|\.collection\(["'`][\w-]+["'`]\)/is;
const serverAuthCheck = /\b(auth|currentUser|getServerSession|getSession|getToken|getUser|getUserOrThrow|verifyIdToken|jwtVerify|verify)\s*\(|requireAuth|withAuth|clerkMiddleware|authMiddleware|isAuthenticated|session\?\.user|userId\b/;
const authorizationCheck = /\b(ownerId|userId|tenantId|orgId|organizationId|workspaceId|memberId|role|permission|permissions|isAdmin|hasAccess|canAccess|authorize|policy|members)\b/is;
const clientRoleSource = /\b(req|request)\.(body|query|headers|cookies)|searchParams|get\(["'`](role|isAdmin|userId|orgId|tenantId|organizationId)["'`]\)|localStorage|sessionStorage/i;

export const rules: Rule[] = [
  textRule(
    {
      id: "auth/jwt-not-verified",
      title: "JWT decoded without signature verification",
      category: "jwt",
      defaultSeverity: "critical",
      whyItMatters: "A decoded JWT is only parsed, not trusted. Attackers can forge claims and access another user's data.",
      recommendation: "Verify the token signature with `jwtVerify`, `jwt.verify`, or the provider's Admin SDK before using claims."
    },
    (file) => {
      const decodeLines = matchingLines(file, /\b(jwt\.decode|jwtDecode|decodeJwt)\s*\(/);
      if (!decodeLines.length || /\b(jwtVerify|jwt\.verify|verifyIdToken)\s*\(/.test(file.text)) return [];
      return decodeLines.map(({ line, text }) => diagnostic(file, line, "auth/jwt-not-verified", text));
    }
  ),
  textRule(
    {
      id: "auth/jwt-none-or-weak-alg",
      title: "JWT verification allows unsafe algorithms",
      category: "jwt",
      defaultSeverity: "critical",
      whyItMatters: "Allowing `none` or request-controlled algorithms can let attackers bypass JWT signature checks.",
      recommendation: "Pin strong expected algorithms in server configuration and never derive the algorithm from request data."
    },
    (file) =>
      matchingLines(file, /algorithms?\s*:\s*(\[[^\]]*["'`]none["'`]|[^,\n]*(req|request|headers|query|body))/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/jwt-none-or-weak-alg", text)
      )
  ),
  textRule(
    {
      id: "auth/jwt-missing-exp",
      title: "JWT verification does not enforce expiration",
      category: "jwt",
      defaultSeverity: "error",
      whyItMatters: "Tokens without enforced expiration can remain valid long after they should have been revoked or rotated.",
      recommendation: "Require an `exp` claim or provider expiration validation when verifying custom JWTs."
    },
    (file) => {
      if (!/\bjwt\.verify\s*\(/.test(file.text)) return [];
      if (/\b(exp|maxTokenAge|clockTolerance)\b/.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /\bjwt\.verify\s*\(/), "auth/jwt-missing-exp", "JWT verification call lacks an explicit expiration policy.")];
    }
  ),
  textRule(
    {
      id: "auth/jwt-missing-audience-issuer",
      title: "JWT verification omits audience or issuer",
      category: "jwt",
      defaultSeverity: "error",
      whyItMatters: "A token from another app or issuer may be accepted if issuer and audience are not checked.",
      recommendation: "Pass expected `issuer` and `audience` to the verifier for provider-issued JWTs."
    },
    (file) => {
      if (!/\bjwtVerify\s*\(/.test(file.text)) return [];
      if (/\bissuer\b/.test(file.text) && /\baudience\b/.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /\bjwtVerify\s*\(/), "auth/jwt-missing-audience-issuer", "JWT verification call does not include both issuer and audience.")];
    }
  ),
  textRule(
    {
      id: "auth/public-env-secret-name",
      title: "Secret-like name uses a public environment prefix",
      category: "secrets",
      defaultSeverity: "critical",
      whyItMatters: "Public environment prefixes can expose sensitive auth material to browser bundles.",
      recommendation: "Move secrets to server-only environment variables and pass only non-sensitive public config to the client."
    },
    (file) =>
      matchingLines(file, /\b(NEXT_PUBLIC_|VITE_|PUBLIC_)[A-Z0-9_]*(SECRET|TOKEN|PRIVATE|SERVICE_ROLE|ADMIN_KEY|JWT)[A-Z0-9_]*/).map(
        ({ line, text }) => diagnostic(file, line, "auth/public-env-secret-name", redactSecretEvidence(text))
      )
  ),
  textRule(
    {
      id: "auth/hardcoded-auth-secret",
      title: "Auth secret appears hardcoded in source",
      category: "secrets",
      defaultSeverity: "error",
      whyItMatters: "Hardcoded auth secrets are hard to rotate and can leak through source control, logs, packages, or client bundles.",
      recommendation: "Move auth secrets to server-only environment variables or a secret manager and rotate any exposed value."
    },
    (file) =>
      matchingLines(file, /\b(jwtSecret|authSecret|clientSecret|sessionSecret|NEXTAUTH_SECRET|JWT_SECRET)\b\s*[:=]\s*["'`][^"'`]{8,}["'`]/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/hardcoded-auth-secret", redactSecretEvidence(text))
      )
  ),
  textRule(
    {
      id: "auth/weak-secret-length",
      title: "Auth secret appears too short",
      category: "secrets",
      defaultSeverity: "warning",
      whyItMatters: "Short signing or session secrets are easier to guess or brute force.",
      recommendation: "Use a high-entropy secret of at least 32 bytes for signing and session encryption."
    },
    (file) =>
      matchingLines(file, /\b(jwtSecret|authSecret|sessionSecret|JWT_SECRET|NEXTAUTH_SECRET)\b\s*[:=]\s*["'`][^"'`]{1,15}["'`]/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/weak-secret-length", redactSecretEvidence(text))
      )
  ),
  textRule(
    {
      id: "auth/supabase-service-key-exposed",
      title: "Supabase service role key can reach browser code",
      category: "provider",
      defaultSeverity: "critical",
      whyItMatters: "A Supabase service role key bypasses RLS and grants broad database access if exposed to the client.",
      recommendation: "Use the anon key in browser code and keep service role operations inside server-only modules."
    },
    (file) => {
      if (!/SUPABASE_SERVICE_ROLE|service_role|SERVICE_ROLE/.test(file.text)) return [];
      if (!isClientReachable(file) && !/NEXT_PUBLIC_SUPABASE_SERVICE_ROLE|VITE_SUPABASE_SERVICE_ROLE/.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /SUPABASE_SERVICE_ROLE|service_role|SERVICE_ROLE/), "auth/supabase-service-key-exposed", "Service role key reference appears in client-reachable code or public env naming.")];
    }
  ),
  textRule(
    {
      id: "auth/service-key-in-client",
      title: "Privileged provider key appears in client-reachable code",
      category: "secrets",
      defaultSeverity: "critical",
      whyItMatters: "Admin, service, and private keys in client code can grant attackers privileged backend access.",
      recommendation: "Move privileged provider calls to server-only routes and expose only narrow application APIs to the browser."
    },
    (file) => {
      if (!isClientReachable(file)) return [];
      return matchingLines(file, /\b(SERVICE_ROLE|PRIVATE_KEY|ADMIN_KEY|FIREBASE_ADMIN|JWT_SECRET|NEXTAUTH_SECRET)\b/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/service-key-in-client", redactSecretEvidence(text))
      );
    }
  ),
  textRule(
    {
      id: "auth/localstorage-token",
      title: "Sensitive token stored in browser storage",
      category: "session",
      defaultSeverity: "warning",
      whyItMatters: "Tokens in localStorage or sessionStorage are exposed to XSS and are hard to protect with cookie flags.",
      recommendation: "Prefer HttpOnly, Secure, SameSite cookies or short-lived in-memory tokens with refresh handled server-side."
    },
    (file) =>
      matchingLines(file, /\b(localStorage|sessionStorage)\.(setItem|getItem)\s*\(\s*["'`][^"'`]*(token|jwt|session|refresh|access)/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/localstorage-token", text)
      )
  ),
  textRule(
    {
      id: "auth/firebase-id-token-not-verified",
      title: "Firebase ID token trusted without Admin SDK verification",
      category: "provider",
      defaultSeverity: "critical",
      whyItMatters: "Firebase ID tokens must be verified with the Admin SDK before claims are trusted server-side.",
      recommendation: "Call `getAuth().verifyIdToken(token)` or `admin.auth().verifyIdToken(token)` before using Firebase claims."
    },
    (file, context) => {
      if (!context.profile.authProviders.includes("firebase") && !/firebase/i.test(file.text)) return [];
      if (!/(idToken|Authorization|Bearer|firebase)/i.test(file.text)) return [];
      if (/\bverifyIdToken\s*\(/.test(file.text)) return [];
      return matchingLines(file, /\b(jwt\.decode|jwtDecode|decodeJwt|JSON\.parse|atob)\s*\(/)
        .filter(({ text }) => /(token|idToken|Authorization|Bearer|firebase)/i.test(text))
        .map(({ line, text }) =>
        diagnostic(file, line, "auth/firebase-id-token-not-verified", text)
      );
    }
  ),
  textRule(
    {
      id: "auth/trusts-client-role",
      title: "Server trusts authorization claims from the request",
      category: "authorization",
      defaultSeverity: "critical",
      whyItMatters: "Roles, tenant IDs, organization IDs, and user IDs supplied by the client can be tampered with.",
      recommendation: "Read identity from the verified server session, then look up roles and tenant membership server-side."
    },
    (file) => {
      if (!isServerRoute(file)) return [];
      return matchingLines(file, /\b(role|isAdmin|userId|orgId|tenantId|organizationId)\b\s*=\s*[^;\n]*(req|request)\.(body|query|headers)|\b(role|isAdmin|userId|orgId|tenantId|organizationId)\b\s*=\s*[^;\n]*searchParams|\b(req|request)\.(body|query|headers)\.[a-zA-Z0-9_]*(role|isAdmin|userId|orgId|tenantId|organizationId)/i).map(
        ({ line, text }) => diagnostic(file, line, "auth/trusts-client-role", text)
      );
    }
  ),
  routeRule(
    {
      id: "auth/no-server-auth-check",
      title: "Protected server route lacks a server-side auth check",
      category: "authentication",
      defaultSeverity: "critical",
      whyItMatters: "Protecting only UI leaves server routes callable directly by unauthenticated users.",
      recommendation: "Identify the current user inside the server handler and reject unauthenticated requests before accessing protected data."
    },
    (file, context) => {
      if (!isHandlerLike(file)) return [];
      if (!isProtectedRouteCandidate(file, context) || !databaseAccess.test(file.text)) return [];
      if (serverAuthCheck.test(file.text)) return [];
      return [diagnostic(file, firstExecutableLine(file), "auth/no-server-auth-check", "Protected-looking route accesses data without a server auth primitive.")];
    }
  ),
  routeRule(
    {
      id: "auth/unprotected-admin-route",
      title: "Admin route lacks explicit server authorization",
      category: "authorization",
      defaultSeverity: "critical",
      whyItMatters: "Admin paths usually protect high-impact operations and need explicit role or permission checks.",
      recommendation: "Require a server-verified admin role or permission before running this handler."
    },
    (file) => {
      if (!/admin/i.test(file.relativePath) || !databaseAccess.test(file.text)) return [];
      if (/\b(isAdmin|role|permission|authorize|hasAccess)\b/i.test(file.text)) return [];
      return [diagnostic(file, firstExecutableLine(file), "auth/unprotected-admin-route", "Admin route accesses data without an explicit admin authorization check.")];
    }
  ),
  routeRule(
    {
      id: "auth/authenticated-not-authorized",
      title: "Route checks authentication but not resource authorization",
      category: "authorization",
      defaultSeverity: "critical",
      whyItMatters: "A logged-in user can still request another user's resource if ownership, tenant, or permission checks are missing.",
      recommendation: "Constrain database queries by both the requested resource ID and the current user's ownership, tenant, membership, role, or permission."
    },
    (file) => {
      if (!serverAuthCheck.test(file.text) || !databaseAccess.test(file.text)) return [];
      if (!/(params\.id|req\.params\.id|request\.nextUrl\.searchParams|get\(["'`]id["'`]\)|findUnique\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*id)/is.test(file.text)) return [];
      if (hasAuthorizationBeyondPresence(file.text)) return [];
      return [diagnostic(file, lineOf(file, /params\.id|req\.params\.id|findUnique/), "auth/authenticated-not-authorized", "Handler verifies a session and loads a requested resource without an ownership or tenant constraint.")];
    }
  ),
  routeRule(
    {
      id: "auth/missing-tenant-scope",
      title: "Multi-tenant data query lacks tenant scope",
      category: "authorization",
      defaultSeverity: "critical",
      whyItMatters: "Queries in tenant-aware routes can leak data across organizations if tenant constraints are absent.",
      recommendation: "Add a verified tenant, organization, or workspace constraint to the database query."
    },
    (file) => {
      if (!/(tenant|org|organization|workspace)/i.test(file.relativePath + file.text)) return [];
      if (!databaseAccess.test(file.text)) return [];
      if (/\b(tenantId|orgId|organizationId|workspaceId)\b\s*[:=]/.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, databaseAccess), "auth/missing-tenant-scope", "Tenant-like route performs a database operation without a tenant/org constraint.")];
    }
  ),
  routeRule(
    {
      id: "auth/insecure-direct-object-reference",
      title: "Route uses arbitrary resource ID without access verification",
      category: "authorization",
      defaultSeverity: "critical",
      whyItMatters: "Using a request-controlled ID without access verification can expose private resources by enumeration.",
      recommendation: "After reading the resource ID, verify access against the current user's membership, ownership, tenant, or permission."
    },
    (file) => {
      if (!/(params\.id|req\.params|searchParams|get\(["'`]id["'`]\))/.test(file.text) || !databaseAccess.test(file.text)) return [];
      if (hasAuthorizationBeyondPresence(file.text)) return [];
      return [diagnostic(file, lineOf(file, /params\.id|req\.params|searchParams/), "auth/insecure-direct-object-reference", "Request-controlled resource ID flows into data access without an access constraint.")];
    }
  ),
  textRule(
    {
      id: "auth/client-only-protection",
      title: "Private flow relies on client-only auth protection",
      category: "authentication",
      defaultSeverity: "critical",
      whyItMatters: "Client redirects and hidden UI do not protect API routes, server actions, or database reads.",
      recommendation: "Move the protection to server routes, server actions, middleware, or server components that validate the session."
    },
    (file) => {
      if (!isPageOrRouteComponent(file)) return [];
      if (!/\b(useSession|useAuth)\s*\(|\b(role|isAdmin)\b\s*={2,3}\s*["'`]admin|router\.push\(["'`]\/login|redirect\(["'`]\/login/.test(file.text)) return [];
      if (!dangerousPath.test(file.relativePath)) return [];
      return [diagnostic(file, lineOf(file, /\buseSession\s*\(|\buseAuth\s*\(|["']use client["']/), "auth/client-only-protection", "Protected-looking page uses client-side auth state as its visible guard.")];
    }
  ),
  textRule(
    {
      id: "auth/admin-claim-not-verified-server-side",
      title: "Admin claim is checked only in client/UI code",
      category: "authorization",
      defaultSeverity: "error",
      whyItMatters: "Admin UI checks can be bypassed unless the server repeats the authorization decision.",
      recommendation: "Re-check admin permissions in the server handler that performs the privileged operation."
    },
    (file) => {
      if (!isClientReachable(file) || !/\b(isAdmin|role\s*={2,3}\s*["'`]admin|role\s*===\s*["'`]admin)/.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /isAdmin|role\s*={2,3}\s*["'`]admin/), "auth/admin-claim-not-verified-server-side", "Admin claim appears in client-reachable UI code.")];
    }
  ),
  textRule(
    {
      id: "auth/insecure-cookie-flags",
      title: "Auth cookie lacks hardened flags",
      category: "cookies",
      defaultSeverity: "error",
      whyItMatters: "Auth cookies without HttpOnly, Secure, and SameSite protections are easier to steal or abuse in browser attacks.",
      recommendation: "Set auth cookies with `httpOnly: true`, `secure: true` in production, and an appropriate `sameSite` value."
    },
    (file) => {
      const cookieLines = matchingLines(file, /(cookies\(\)\.set|res\.cookie|Set-Cookie|serialize\()/i);
      if (!cookieLines.length) return [];
      if (/httpOnly\s*:\s*true/i.test(file.text) && /secure\s*:\s*true|secure;\s*/i.test(file.text) && /sameSite|SameSite/i.test(file.text)) return [];
      return cookieLines.slice(0, 1).map(({ line, text }) => diagnostic(file, line, "auth/insecure-cookie-flags", text));
    }
  ),
  routeRule(
    {
      id: "auth/missing-csrf-state-changing-route",
      title: "Cookie-authenticated state-changing route lacks CSRF protection",
      category: "csrf",
      defaultSeverity: "error",
      whyItMatters: "Browsers automatically send cookies, so unsafe methods need CSRF protection unless they use non-cookie auth.",
      recommendation: "Validate a CSRF token, same-origin header, webhook signature, or other request authenticity proof before mutating state."
    },
    (file) => {
      if (!/\b(POST|PUT|PATCH|DELETE)\b/.test(file.text) || !/(cookies\(\)|req\.cookies|cookie)/i.test(file.text)) return [];
      if (/\b(csrf|same-origin|origin|referer|webhook|signature)\b/i.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /\b(POST|PUT|PATCH|DELETE)\b/), "auth/missing-csrf-state-changing-route", "Unsafe method appears to use cookie auth without CSRF or origin validation.")];
    }
  ),
  textRule(
    {
      id: "auth/oauth-missing-state",
      title: "OAuth flow does not validate state",
      category: "oauth",
      defaultSeverity: "critical",
      whyItMatters: "Missing OAuth state validation can allow login CSRF or callback confusion attacks.",
      recommendation: "Generate a random state value before redirect and validate it during the callback."
    },
    (file) => {
      if (!/(authorize\?|\/oauth\/authorize|response_type=["'`]code)/i.test(file.relativePath + "\n" + file.text)) return [];
      if (/NextAuth|from ["'`]next-auth|supabase\.auth|exchangeCodeForSession|signInWithOtp|resetPasswordForEmail/i.test(file.text)) return [];
      if (/\bstate\b/.test(file.text)) return [];
      return [diagnostic(file, firstExecutableLine(file), "auth/oauth-missing-state", "OAuth-like handler does not mention state generation or validation.")];
    }
  ),
  textRule(
    {
      id: "auth/oauth-open-redirect",
      title: "OAuth redirect URL can be attacker controlled",
      category: "oauth",
      defaultSeverity: "critical",
      whyItMatters: "Open redirects in auth flows can steal tokens or send users to phishing pages after login.",
      recommendation: "Only redirect to allowlisted relative paths or trusted origins after callback handling."
    },
    (file) =>
      matchingLines(file, /(redirect|NextResponse\.redirect|res\.redirect)\s*\([^)]*(next|callbackUrl|redirectUrl|req\.query|searchParams)/i)
        .filter(({ text }) => !/isSafeRedirect|allowlisted|sanitize|safeRedirect/i.test(text))
        .filter(({ text }) => !/req\.session\.returnTo/.test(text) || !/isSafeRedirect/.test(file.text))
        .map(
        ({ line, text }) => diagnostic(file, line, "auth/oauth-open-redirect", text)
      )
  ),
  textRule(
    {
      id: "auth/authjs-unsafe-callback-role",
      title: "Auth.js callback copies role into session without validation",
      category: "provider",
      defaultSeverity: "error",
      whyItMatters: "Provider or token role claims can drift from your database authorization model if copied without server validation.",
      recommendation: "Resolve roles from your database or authorization service inside the callback before adding them to the session."
    },
    (file) => {
      if (!/(NextAuth|callbacks|session\s*\(|jwt\s*\()/.test(file.text)) return [];
      return matchingLines(file, /session\.user\.(role|isAdmin|orgId|tenantId)\s*=\s*(token|user|profile)\./).map(({ line, text }) =>
        diagnostic(file, line, "auth/authjs-unsafe-callback-role", text)
      );
    }
  ),
  textRule(
    {
      id: "auth/clerk-client-only-auth",
      title: "Clerk auth is only used in client code for protected data",
      category: "provider",
      defaultSeverity: "error",
      whyItMatters: "Clerk client hooks are useful for UI state, but protected data still needs server-side `auth()` checks or middleware coverage.",
      recommendation: "Use Clerk `auth()` or middleware in server routes and verify organization or role membership server-side."
    },
    (file) => {
      if (!isPageOrRouteComponent(file) || !isClientReachable(file) || !/\b(useAuth|useUser|SignedIn|SignedOut)\b/.test(file.text)) return [];
      if (!dangerousPath.test(file.relativePath)) return [];
      return [diagnostic(file, lineOf(file, /\b(useAuth|useUser|SignedIn|SignedOut)\b/), "auth/clerk-client-only-auth", "Clerk client UI primitive guards a protected-looking page.")];
    }
  ),
  routeRule(
    {
      id: "auth/middleware-after-route",
      title: "Auth middleware is registered after sensitive routes",
      category: "middleware",
      defaultSeverity: "error",
      whyItMatters: "Express middleware registered after a route cannot protect requests that already reached the handler.",
      recommendation: "Register `requireAuth` or equivalent middleware before sensitive routes, or attach it directly to each sensitive route."
    },
    (file) => {
      if (!/\b(app|router)\.(get|post|put|patch|delete)\s*\(/.test(file.text) || !/\b(app|router)\.use\s*\([^)]*(auth|requireAuth|session)/i.test(file.text)) return [];
      const routeIndex = file.text.search(/\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*["'`][^"'`]*(admin|dashboard|billing|private|users)/i);
      const middlewareIndex = file.text.search(/\b(app|router)\.use\s*\([^)]*(auth|requireAuth|session)/i);
      if (routeIndex === -1 || middlewareIndex === -1 || middlewareIndex < routeIndex) return [];
      return [diagnostic(file, lineFromIndex(file.text, routeIndex), "auth/middleware-after-route", "Auth middleware is registered after a sensitive route declaration.")];
    }
  ),
  textRule(
    {
      id: "auth/missing-middleware-coverage",
      title: "Protected route candidates lack middleware coverage",
      category: "middleware",
      defaultSeverity: "error",
      whyItMatters: "Protected-looking routes need middleware or route-local server checks; otherwise direct requests may bypass UI guards.",
      recommendation: "Add middleware coverage for protected route groups or add explicit server auth checks in each handler."
    },
    (file, context) => {
      if (!context.profile.protectedRouteCandidates.length) return [];
      if (!/middleware\.[cm]?[jt]s$/.test(file.relativePath)) return [];
      const missing = context.profile.protectedRouteCandidates.find((route) => {
        const routeLocalFile = context.files.find((candidate) => candidate.relativePath.startsWith(route));
        if (routeLocalFile && serverAuthCheck.test(routeLocalFile.text)) return false;
        const normalized = route.replace(/^app\/api\//, "/api/").replace(/^pages\/api\//, "/api/").replace(/^app\//, "/");
        const firstSegment = normalized.split("/").filter(Boolean)[0];
        return firstSegment && !file.text.includes(`/${firstSegment}`) && !file.text.includes(`${firstSegment}/`);
      });
      if (!missing) return [];
      return [diagnostic(file, lineOf(file, /matcher|config|export/), "auth/missing-middleware-coverage", `Middleware may not cover protected route candidate ${missing}.`)];
    }
  ),
  textRule(
    {
      id: "auth/next-middleware-matcher-gap",
      title: "Next.js middleware matcher misses protected APIs",
      category: "middleware",
      defaultSeverity: "error",
      whyItMatters: "Middleware matcher gaps can leave protected routes callable even when pages appear guarded.",
      recommendation: "Include protected app routes and API routes in the matcher, or add route-local server auth checks."
    },
    (file, context) => {
      if (!/middleware\.[cm]?[jt]s$/.test(file.relativePath) || !/matcher\s*:/.test(file.text)) return [];
      if (/\/api|api\//.test(file.text)) return [];
      const hasProtectedApi = context.files.some((candidate) => /(^|\/)(app\/api|pages\/api)\/(admin|private|billing|users|projects)/i.test(candidate.relativePath));
      if (!hasProtectedApi) return [];
      return [diagnostic(file, lineOf(file, /matcher\s*:/), "auth/next-middleware-matcher-gap", "Middleware matcher does not include `/api` while protected-looking API routes exist.")];
    }
  ),
  textRule(
    {
      id: "auth/public-glob-too-broad",
      title: "Public route glob appears too broad",
      category: "middleware",
      defaultSeverity: "error",
      whyItMatters: "Broad public globs can accidentally include admin, billing, API, or private routes.",
      recommendation: "Make public route allowlists narrow and explicit; keep protected route groups outside public patterns."
    },
    (file) =>
      matchingLines(file, /\b(publicRoutes|publicPaths|ignoredRoutes|skipAuth)\b[^;\n]*(\*\*|\/:\w+\*|\/\(\.\*\)|\/\*)/i)
        .filter(({ text }) => /(admin|billing|private|api|dashboard|\*\*)/i.test(text))
        .map(({ line, text }) => diagnostic(file, line, "auth/public-glob-too-broad", text))
  ),
  textRule(
    {
      id: "auth/express-missing-next-on-deny",
      title: "Express auth middleware denial path may continue",
      category: "middleware",
      defaultSeverity: "warning",
      whyItMatters: "Middleware that sends a denial response and then continues can accidentally run protected handlers.",
      recommendation: "Return immediately after denial responses and call `next()` only after successful authentication."
    },
    (file) => {
      if (!/express|NextFunction|app\.use|router\.use/.test(file.text)) return [];
      return matchingLines(file, /(res\.status\((401|403)\)|res\.sendStatus\((401|403)\)).*\bnext\s*\(/i).map(({ line, text }) =>
        diagnostic(file, line, "auth/express-missing-next-on-deny", text)
      );
    }
  ),
  textRule(
    {
      id: "auth/oauth-missing-pkce",
      title: "OAuth public client flow does not use PKCE",
      category: "oauth",
      defaultSeverity: "error",
      whyItMatters: "Public OAuth clients should use PKCE so intercepted authorization codes cannot be redeemed by attackers.",
      recommendation: "Generate a `code_verifier`, send a `code_challenge`, and verify the code exchange with PKCE."
    },
    (file) => {
      if (!/(authorize\?|grant_type=["'`]authorization_code|response_type=["'`]code)/i.test(file.relativePath + "\n" + file.text)) return [];
      if (/supabase\.auth|exchangeCodeForSession|signInWithOtp|resetPasswordForEmail/i.test(file.text)) return [];
      if (/\b(code_challenge|code_verifier|S256|pkce)\b/i.test(file.text)) return [];
      return [diagnostic(file, firstExecutableLine(file), "auth/oauth-missing-pkce", "OAuth authorization-code flow does not mention PKCE.")];
    }
  ),
  textRule(
    {
      id: "auth/long-session-ttl",
      title: "Session lifetime appears unusually long",
      category: "session",
      defaultSeverity: "warning",
      whyItMatters: "Long-lived sessions increase the impact of token theft and stale privileges.",
      recommendation: "Use a shorter session lifetime and rotate or revalidate sessions for sensitive operations."
    },
    (file) =>
      matchingLines(file, /\b(maxAge|expiresIn|sessionMaxAge|SESSION_TTL)\b\s*[:=]\s*(?:60\s*\*\s*60\s*\*\s*24\s*\*\s*(?:3[1-9]|[4-9]\d|\d{3,})|[3-9]\d{6,})/i)
        .filter(({ text }) => /(session|jwt|token|cookie)/i.test(text))
        .map(
        ({ line, text }) => diagnostic(file, line, "auth/long-session-ttl", text)
      )
  ),
  textRule(
    {
      id: "auth/session-fixation-risk",
      title: "Login flow may not rotate the session",
      category: "session",
      defaultSeverity: "error",
      whyItMatters: "Reusing a pre-login session after authentication can expose users to session fixation attacks.",
      recommendation: "Regenerate, rotate, or issue a new session identifier after login and privilege elevation."
    },
    (file) => {
      if (!/(login|signin|sign-in|callback)/i.test(file.relativePath + file.text)) return [];
      if (!isServerRoute(file)) return [];
      if (/supabase\.auth|signInWithOtp|exchangeCodeForSession|resetPasswordForEmail/i.test(file.text)) return [];
      if (!/(session|cookie).*(set|create)|res\.cookie|cookies\(\)\.set/i.test(file.text)) return [];
      if (/\b(regenerate|rotate|renew|destroy|invalidate|newSession)\b/i.test(file.text)) return [];
      return [diagnostic(file, firstExecutableLine(file), "auth/session-fixation-risk", "Login-like flow sets session material without visible rotation/regeneration.")];
    }
  ),
  textRule(
    {
      id: "auth/cookie-domain-too-broad",
      title: "Auth cookie domain is broader than necessary",
      category: "cookies",
      defaultSeverity: "warning",
      whyItMatters: "Broad cookie domains share auth cookies with more subdomains, increasing exposure if any subdomain is compromised.",
      recommendation: "Omit the cookie domain when possible or scope it to the narrowest host that needs the cookie."
    },
    (file) =>
      matchingLines(file, /\bdomain\s*:\s*["'`]\.[^"'`]+["'`]|Domain=\.[^;]+/i).map(({ line, text }) =>
        diagnostic(file, line, "auth/cookie-domain-too-broad", text)
      )
  ),
  textRule(
    {
      id: "auth/jwt-secret-client-exposed",
      title: "JWT secret can reach client code",
      category: "jwt",
      defaultSeverity: "critical",
      whyItMatters: "A client-exposed JWT secret lets attackers mint or tamper with trusted tokens.",
      recommendation: "Keep JWT signing secrets in server-only environment variables and modules."
    },
    (file) => {
      if (!isClientReachable(file)) return [];
      return matchingLines(file, /\b(NEXT_PUBLIC_|VITE_|PUBLIC_)?[A-Z0-9_]*JWT[A-Z0-9_]*(SECRET|KEY)|\bJWT_SECRET\b/i).map(({ line, text }) =>
        diagnostic(file, line, "auth/jwt-secret-client-exposed", redactSecretEvidence(text))
      );
    }
  ),
  textRule(
    {
      id: "auth/supabase-rls-disabled",
      title: "Supabase table appears to lack RLS protection",
      category: "database",
      defaultSeverity: "critical",
      whyItMatters: "Tables exposed through Supabase should have RLS enabled with policies to prevent broad data access.",
      recommendation: "Enable RLS for public tables and add policies scoped to authenticated users, owners, or tenants."
    },
    (file, context) => {
      if (!file.relativePath.endsWith(".sql") || !/create\s+table/i.test(file.text)) return [];
      if (!context.profile.authProviders.includes("supabase") && !/supabase/i.test(file.relativePath)) return [];
      if (/enable\s+row\s+level\s+security|alter\s+table[^;]+enable\s+row\s+level\s+security/i.test(file.text)) return [];
      return [diagnostic(file, lineOf(file, /create\s+table/i), "auth/supabase-rls-disabled", "SQL migration creates a table without enabling row level security nearby.")];
    }
  )
];

function textRule(meta: RuleMeta, runFile: (file: SourceFile, context: RuleContext) => Diagnostic[]): Rule {
  return {
    ...meta,
    appliesTo: () => true,
    run: (context) => context.files.flatMap((file) => attachMeta(runFile(file, context), meta))
  };
}

function routeRule(meta: RuleMeta, runFile: (file: SourceFile, context: RuleContext) => Diagnostic[]): Rule {
  return {
    ...meta,
    appliesTo: () => true,
    run: (context) => context.routeFiles.flatMap((file) => attachMeta(runFile(file, context), meta))
  };
}

function diagnostic(file: SourceFile, line: number, ruleId: string, evidence: string): Diagnostic {
  return {
    ruleId,
    title: "",
    severity: "info",
    category: "authentication",
    file: file.relativePath,
    line,
    confidence: "high",
    evidence: [cleanEvidence(evidence)],
    whyItMatters: "",
    recommendation: "",
    suppressionHint: `// auth-doctor-disable-next-line ${ruleId}`
  };
}

function attachMeta(diagnostics: Diagnostic[], meta: RuleMeta): Diagnostic[] {
  return diagnostics.map((diagnostic) => ({
    ...diagnostic,
    title: meta.title,
    severity: meta.defaultSeverity,
    category: meta.category,
    whyItMatters: meta.whyItMatters,
    recommendation: meta.recommendation,
    docs: meta.docs
  }));
}

function matchingLines(file: SourceFile, pattern: RegExp): Array<{ line: number; text: string }> {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  const globalPattern = new RegExp(pattern.source, flags);
  const out: Array<{ line: number; text: string }> = [];
  const lines = file.text.split(/\r?\n/);
  lines.forEach((text, index) => {
    globalPattern.lastIndex = 0;
    if (globalPattern.test(text)) out.push({ line: index + 1, text });
  });
  return out;
}

function lineOf(file: SourceFile, pattern: RegExp): number {
  const lines = file.text.split(/\r?\n/);
  return Math.max(
    1,
    lines.findIndex((line) => {
      pattern.lastIndex = 0;
      return pattern.test(line);
    }) + 1
  );
}

function lineFromIndex(text: string, index: number): number {
  return text.slice(0, Math.max(0, index)).split(/\r?\n/).length;
}

function firstExecutableLine(file: SourceFile): number {
  const lines = file.text.split(/\r?\n/);
  const index = lines.findIndex((line) => line.trim() && !line.trim().startsWith("//") && !line.trim().startsWith("import"));
  return index === -1 ? 1 : index + 1;
}

function isClientReachable(file: SourceFile): boolean {
  return (
    /["']use client["']/.test(file.text) ||
    /\.(client|browser)\.[cm]?[jt]sx?$/.test(file.relativePath) ||
    /(^|\/)(components|pages)\/.+\.[cm]?[jt]sx?$/.test(file.relativePath) ||
    /(^|\/)app\/.+\.[cm]?[jt]sx$/.test(file.relativePath)
  );
}

function isPageOrRouteComponent(file: SourceFile): boolean {
  return /(^|\/)(page|layout|route)\.[cm]?[jt]sx?$/.test(file.relativePath) || /(^|\/)pages\//.test(file.relativePath);
}

function isServerRoute(file: SourceFile): boolean {
  return /(^|\/)(route|server|app)\.[cm]?[jt]s$/.test(file.relativePath) || /(^|\/)(api|routes|controllers)\//.test(file.relativePath);
}

function isHandlerLike(file: SourceFile): boolean {
  return /\b(GET|POST|PUT|PATCH|DELETE)\s*\(|\b(req|request|res|response)\b|NextRequest|Request\b|Response\b|\b(app|router)\.(get|post|put|patch|delete)\s*\(/.test(file.text);
}

function isProtectedRouteCandidate(file: SourceFile, context: RuleContext): boolean {
  if (dangerousPath.test(file.relativePath)) return true;
  return context.profile.protectedRouteCandidates.some((route) => file.relativePath.includes(route.replace(/^\//, "")));
}

function hasAuthorizationBeyondPresence(text: string): boolean {
  if (!authorizationCheck.test(text)) return false;
  if (/session\?\.user|if\s*\(\s*!?session|if\s*\(\s*!?user|if\s*\(\s*!?userId/.test(text) && !/\b(ownerId|tenantId|orgId|organizationId|workspaceId|members|role|permission|isAdmin)\b/.test(text)) {
    return false;
  }
  if (clientRoleSource.test(text) && !/\b(session|currentUser|authUser|verified|database|db|prisma)\b/i.test(text)) return false;
  return true;
}

function cleanEvidence(value: string): string {
  const trimmed = value.trim().replace(/\s+/g, " ");
  return trimmed.length > 160 ? `${trimmed.slice(0, 157)}...` : trimmed;
}

function redactSecretEvidence(value: string): string {
  const variable = /([A-Z0-9_]*(SECRET|TOKEN|PRIVATE|SERVICE_ROLE|ADMIN_KEY|JWT)[A-Z0-9_]*)/i.exec(value)?.[1];
  return variable ? `Secret-like variable reference: ${variable}` : "Secret-like variable reference found; value redacted.";
}

export function getRuleById(ruleId: string): Rule | undefined {
  return rules.find((rule) => rule.id === ruleId);
}
