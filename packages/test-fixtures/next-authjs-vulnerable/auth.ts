import NextAuth from "next-auth";

export const { handlers, auth } = NextAuth({
  callbacks: {
    session({ session, token }) {
      session.user.role = token.role;
      return session;
    }
  }
});

