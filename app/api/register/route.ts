import axios from "axios";
import { genSalt, hash } from "bcrypt";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import prisma from "../../../db/index";
import { generateJWT } from "../../../lib/auth";
import { RegisterUserSchema } from "../../../schema/registerSchema";

export async function POST(request: NextRequest) {
  const requestBody = await request.json();
  const validateData = RegisterUserSchema.parse(requestBody);
  if (
    validateData.email !== requestBody.email ||
    validateData.password !== requestBody.password ||
    validateData.firstName !== requestBody.firstName ||
    validateData.lastName !== requestBody.lastName
  ) {
    return NextResponse.json({
      status: 400,
      message: "Invalid Credentials",
    });
  }
  const { firstName, lastName, email, password } = validateData;

  const userExists = await prisma.user.findUnique({
    where: {
      email,
    },
  });
  if (userExists) {
    return NextResponse.json({
      status: 400,
      message: "User Already Exists",
    });
  }

  const unverifiedUser = await prisma.unverifiedUser.create({
    data: {
      firstName,
      lastName,
      email,
      password: await hash(password, await genSalt(10)),
      expiresAt: new Date(new Date().getTime() + 10 * 60 * 1000),
    },
  });
  if (!unverifiedUser) {
    return NextResponse.json({
      status: 400,
      message: "Something went wrong",
    });
  }
  cookies().set({
    name: "userDoc",
    value: generateJWT({ email: unverifiedUser.email, id: unverifiedUser.id }),
  });
  const { data } = await axios.post("/api/sendMail", {
    email: unverifiedUser.email,
  });
  if (data.status !== 200) {
    return NextResponse.json({
      status: data.status,
      message: data.message,
    });
  }

  return NextResponse.json({
    message: "Account Created Successfully",
    status: 200,
  });
}
