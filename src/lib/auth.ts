import NextAuth from "next-auth";
import Credentials from "next-auth/providers/credentials";
import { v4 as uuid } from "uuid";
import db from "./db/db";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { encode as defaultEncode } from "next-auth/jwt";
import { schema } from "./schema";
import * as argon2 from "argon2";

declare module "next-auth" {
  interface Session {
    permissions: string;
  }
}

const adapter = PrismaAdapter(db);

export const { auth, handlers, signIn } = NextAuth({
  adapter,
  providers: [
    Credentials({
      credentials: {
        email: {},
        password: {},
      },
      authorize: async (credentials) => {
        const validatedCredentials = schema.parse(credentials);

        const user = await db.user.findFirst({
          where: {
            email: validatedCredentials.email,
          },
        });
        if (!user) {
          throw new Error("Invalid User Not Found");
        }
        if (
          !(await argon2.verify(
            user.password as string,
            validatedCredentials.password
          ))
        ) {
          throw new Error("Wrong Password");
        }
        return user;
      },
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      if (account?.provider === "credentials") {
        token.credentials = true;
      }
      return token;
    },
    async session({ session }) {
      const permission: string = "1234";
      session.permissions = permission;
      console.log(session);
      return session;
    },
  },
  jwt: {
    encode: async function (params) {
      if (params.token?.credentials) {
        const sessionToken = uuid();

        if (!params.token.sub) {
          throw new Error("No user ID found in token");
        }

        const createdSession = await adapter?.createSession?.({
          sessionToken: sessionToken,
          userId: params.token.sub,
          expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        });

        if (!createdSession) {
          throw new Error("Failed to create session");
        }

        return sessionToken;
      }
      return defaultEncode(params);
    },
  },
});
