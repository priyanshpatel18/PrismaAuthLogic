import axios from "axios";
import Credentials from "next-auth/providers/credentials";
import GithubCredentials from "next-auth/providers/github";
import GoogleCredentials from "next-auth/providers/google";
import { sign } from "jsonwebtoken";

export function generateJWT(payload: any) {
  const SECRET_KEY = process.env.SECRET_KEY || "";

  return sign({ payload }, SECRET_KEY);
}

export async function verifyUser(email: string, password: string) {
  const url = "http://localhost:3000/api/auth/login";

  const headers = {
    "Client-Service": process.env.APP_CLIENT_SERVICE || "",
    "Auth-Key": process.env.APP_AUTH_KEY || "",
    "Content-Type": "application/x-www-form-urlencoded",
  };

  const body = new URLSearchParams();
  body.append("email", email);
  body.append("password", password);

  try {
    const { data } = await axios.post(url, body, { headers });
    console.log(data);

    if (data.status == 401) {
      throw new Error(`HTTP error! Status: ${data.status}`);
    }

    return data as any;
  } catch (error) {
    console.error("Error validating user:", error);
    return {
      data: null,
    };
  }
}

export const authOptions = {
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "email", type: "text", placeholder: "" },
        password: { label: "password", type: "password", placeholder: "" },
      },
      authorize: async (credentials: any): Promise<any> => {
        const { user } = await verifyUser(
          credentials.email,
          credentials.password
        );

        if (user !== null) {
          return {
            id: user.id,
            email: user.email,
          };
        }

        return null;
      },
    }),
    GoogleCredentials({
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      clientId: process.env.GOOGLE_CLIENT_ID!,
    }),
    GithubCredentials({
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
      clientId: process.env.GITHUB_CLIENT_ID!,
    }),
  ],
  secret: process.env.SECRET_KEY || "SeCr3T",
  callbacks: {
    jwt: async ({ token, user }: any) => {
      if (user) {
        token.id = user.id;
        token.token = user.token || "undefined";
        token.displayName = user.displayName || "undefined";
      }
      return token;
    },
    session: async ({ session, token }: any) => {
      if (session?.user) {
        session.user.id = token.id;
        session.user.displayName = token.displayName;
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
  },
};
