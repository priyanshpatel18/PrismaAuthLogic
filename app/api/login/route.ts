import { NextRequest, NextResponse } from "next/server";
import { LoginUserSchema } from "../../../schema/loginSchema";
import prisma from "../../../db";
import { compare } from "bcrypt";
import { generateJWT } from "../../../lib/auth";
import { cookies } from "next/headers";

export async function POST(request: NextRequest) {
  const requestBody = await request.json();
  const { email, password } = requestBody;
  const validateData = LoginUserSchema.parse(requestBody);
  if (validateData.email !== email || validateData.password !== password) {
    return NextResponse.json({ status: 400, message: "Invalid Credentials" });
  }

  const userExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (!userExists) {
    return NextResponse.json({ status: 400, message: "User Not Found" });
  }

  const passwordMatch = await compare(password, userExists.password);
  if (!passwordMatch) {
    return NextResponse.json({ status: 400, message: "Incorrect Password" });
  }

  const token = generateJWT({ email: userExists.email, id: userExists.id });
  cookies().set("token", token);

  return NextResponse.json({ status: 200, message: "Login Successfully" });
}
