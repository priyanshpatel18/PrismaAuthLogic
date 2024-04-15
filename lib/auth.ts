import { sign, verify } from "jsonwebtoken";
import Credentials from "next-auth/providers/credentials";
import { cookies } from "next/headers";
import prisma from "../db/index";
import { LoginUserSchema } from "../schema/loginSchema";
import { compare } from "bcrypt";
import GoogleCredentials from "next-auth/providers/google";
import GithubCredentials from "next-auth/providers/github";

export function generateJWT(payload: any) {
  const SECRET_KEY = process.env.SECRET_KEY || "";

  return sign({ payload }, SECRET_KEY);
}

export function verifyJWT(token: string) {
  const SECRET_KEY = process.env.SECRET_KEY || "";

  const decodedToken = verify(token, SECRET_KEY);
  if (
    !decodedToken ||
    typeof decodedToken !== "object" ||
    !decodedToken.payload
  ) {
    return { status: 400, message: "Invalid Token" };
  }

  return { status: 200, payload: decodedToken.payload };
}

export const authOptions = {
  providers: [
    Credentials({
      name: "Credentials",
      credentials: {
        email: { label: "email", type: "text", placeholder: "" },
        password: { label: "password", type: "password", placeholder: "" },
      },
      authorize: async (credentials) => {
        // Validate Request
        const { email, password } = LoginUserSchema.parse(credentials);
        if (!email || !password) {
          return null;
        }

        try {
          // Check if User exists
          const userExists = await prisma.user.findFirst({
            where: {
              email,
            },
          });
          if (!userExists) {
            return null;
          }

          // Compare Password
          const passwordMatch = await compare(password, userExists.password);
          if (!passwordMatch) {
            return null;
          }

          // Generate JWT if credentials are valid
          const token = generateJWT({
            id: userExists.id.toString(),
            email: userExists.email,
          });
          cookies().set("token", token);

          // Return User
          return {
            id: userExists.id.toString(),
            email: userExists.email,
          };
        } catch (error) {
          console.log(error);
          return null;
        }
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
  pages: {
    signIn: "/login",
  },
};
