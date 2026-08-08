// Demo target for find_ac_points_js -- exercises every library, every
// category, and every match strategy in datasets/ac_functions_js.json in
// one file. Doesn't need to compile or resolve any of these packages; it
// exists purely as scan input, the same role examples/src/ac_demo.rs plays
// for find_ac_points_src.

import passport from "passport";
import jwt from "jsonwebtoken";
import expressjwt from "express-jwt";
import { UseGuards, SetMetadata } from "@nestjs/common";
import { can, defineAbility } from "@casl/ability";
import { enforceSync } from "casbin";
import { getServerSession } from "next-auth";
import NextAuth from "next-auth";
import { verifyIdToken } from "firebase-admin/auth";
import { requiresAuth } from "express-openid-connect";
import { ensureLoggedIn } from "connect-ensure-login";

// passport -- call+import, authentication
function mountAdminRoute() {
  router.get("/admin", passport.authenticate("jwt", { session: false }), handler);
}

// passport -- reference+import, authentication (middleware passed by reference)
function mountLegacyRoute() {
  router.use(passport.authenticate);
}

// jsonwebtoken -- call+import, authentication
function verifyUserToken(token: string, secret: string) {
  return jwt.verify(token, secret);
}

// express-jwt -- call+import, authentication
function buildJwtMiddleware() {
  return expressjwt({ secret, algorithms: ["HS256"] });
}

// nestjs-authz -- call+import, authorization (decorator)
@UseGuards(JwtAuthGuard, RolesGuard)
class AdminController {}

// nestjs-authz -- call+import, authorization (generic pattern, import-gated)
@SetMetadata("roles", ["admin"])
function markAdminOnly() {}

// casl -- call+import, authorization (generic pattern, import-gated)
function userCanEdit(user, doc) {
  return can(user, "edit", doc);
}

// casl -- call+import, authorization
const articleAbility = defineAbility((allow) => {
  allow("read", "Article");
});

// casbin-node -- call+import, policy-enforcement
function evaluatePolicy(sub, obj, act) {
  return enforceSync(sub, obj, act);
}

// next-auth -- call+import, session
async function currentSession(req) {
  return await getServerSession(req);
}

// next-auth -- call+import, authentication (Auth.js v5 central config --
// see "A locally re-exported wrapper" in AC_FINDER_JS.md for why this is
// cataloged separately from the "auth" pattern above)
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [],
});

// firebase-admin-auth -- call+import, authentication
async function verifyFirebaseToken(idToken: string) {
  return await verifyIdToken(idToken);
}

// auth0 -- call+import, authentication
function mountProfileRoute() {
  router.get("/profile", requiresAuth(), profileHandler);
}

// connect-ensure-login -- call+import, authentication
function mountDashboardRoute() {
  router.get("/dashboard", ensureLoggedIn("/login"), dashboardHandler);
}

// generic-authz-checks -- call-only, authorization (no SDK to import-confirm against)
function gateReportsAccess(user) {
  return hasPermission(user, "reports:view");
}

// generic-authz-checks -- reference, authentication (middleware passed by reference)
function mountSettingsRoute() {
  router.get("/settings", requireAuth, settingsHandler);
}

// raw-http-authz -- http+path-hint, raw-http
async function introspectToken(token: string) {
  const url = `${authBase}/introspect`;
  const res = await fetch(url, { method: "POST", body: new URLSearchParams({ token }) });
  return res.json();
}

// raw-http-authz -- suppressed by default (no known AC path nearby); only
// shows up with --all-http-calls
async function pingHealth() {
  return await fetch("/api/health");
}
